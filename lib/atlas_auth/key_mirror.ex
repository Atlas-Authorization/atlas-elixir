defmodule AtlasAuth.KeyMirror.Store do
  @moduledoc """
  What `AtlasAuth.KeyMirror` needs from storage: put / get / get-by-hash / mark-revoked,
  the revocation-feed cursor and the last completed sync time. A store is a
  `{module, ref}` pair; every callback receives `ref` first.

  A mirrored key is a map with the keys `:id`, `:hash` (sha256 of the secret, lowercase
  hex; never the secret), `:prefix`, `:subject_type`, `:subject_id`, `:name`, `:scopes`,
  `:allowed_ips`, `:expires_at` (epoch ms or nil), `:revoked_at` (epoch ms or nil),
  `:organization_id`, `:revoked_reason`.
  """
  @type key :: map()
  @callback put(ref :: term(), key()) :: :ok
  @callback get(ref :: term(), id :: String.t()) :: key() | nil
  @callback get_by_hash(ref :: term(), hash :: String.t()) :: key() | nil
  @callback mark_revoked(ref :: term(), id :: String.t(), revoked_at :: integer(), reason :: String.t() | nil) :: :ok
  @callback mark_membership_ended(ref :: term(), user_id :: String.t(), org_id :: String.t(), revoked_at :: integer()) :: :ok
  @callback get_cursor(ref :: term()) :: String.t() | nil
  @callback set_cursor(ref :: term(), cursor :: String.t()) :: :ok
  @callback get_last_sync_at(ref :: term()) :: integer() | nil
  @callback set_last_sync_at(ref :: term(), at :: integer()) :: :ok
end

defmodule AtlasAuth.KeyMirror do
  @moduledoc """
  A local, authoritative mirror of end-user API keys (`ak_`), with Atlas as the minting
  and revocation backstop.

  Your request path verifies a presented key against the LOCAL row (sha256 hash, scopes,
  expiry, revocation) with no network call. Atlas mints and imports keys and is told about
  every revoke; a revoke made anywhere else reaches the mirror through `sync/1` (the
  `/v1/api_keys/revoked` feed) or `apply_webhook/2` (the `api_key.*` webhooks). Revoking
  locally happens FIRST, so a failed Atlas call never leaves a key usable here.

      mirror = AtlasAuth.KeyMirror.new(client: Atlas.new(secret_key), store: {AtlasAuth.KeyMirror.MemoryStore, store_pid})
      {:ok, created} = AtlasAuth.KeyMirror.mint(mirror, %{subject_type: "user", subject_id: "usr_1", name: "ci"})
      {:ok, %{key: key, effective_scopes: scopes}} = AtlasAuth.KeyMirror.verify(mirror, presented_secret)

  Options for `new/1`: `:client` (an `Atlas.Client`) and `:store` (required); `:api` (a module
  with the `Atlas.ApiKeys` functions, default `Atlas.ApiKeys`); `:scope_implications` (the
  instance's `scopeImplications` map, so a local scope check matches Atlas); `:allowed_scopes`;
  `:verify_at_atlas` (on a local miss ask Atlas to verify the secret; needed for keys imported
  with a bcrypt or Argon2id hash); `:max_staleness_ms` (refuse with `{:error, {:stale, last_sync_at}}`
  when the mirror never synced or last synced longer ago; unset turns it off, for webhook-only
  mirrors); `:serve_stale_for_ms` and `:on_serve_stale` (answer from the last data for this long
  after staleness, with `stale: true`); `:membership` (a function `(user_id, org_id) -> membership map | nil`
  with `"permissions"` for keys bound to an organization); `:now_ms` (zero-arity clock).

  `verify/3` errors: `:invalid`, `:ip_not_allowed`, `:client_ip_required`, `:membership_unresolved`,
  `{:insufficient_scope, missing}`, `{:stale, last_sync_at}`.
  """
  import Bitwise

  defstruct [:client, :store, :api, :now, implications: %{}, allowed: [], opts: []]

  @type t :: %__MODULE__{}

  @doc "Build a mirror. See the module doc for the options."
  @spec new(keyword()) :: t()
  def new(opts) do
    %__MODULE__{
      client: opts[:client],
      store: Keyword.fetch!(opts, :store),
      api: Keyword.get(opts, :api, Atlas.ApiKeys),
      now: Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end),
      implications: Keyword.get(opts, :scope_implications, %{}),
      allowed: Keyword.get(opts, :allowed_scopes, []),
      opts: opts
    }
  end

  @doc "sha256 hex of a secret: the hash the mirror stores and Atlas imports as `sha256_hex`."
  @spec hash_secret(String.t()) :: String.t()
  def hash_secret(secret), do: :crypto.hash(:sha256, secret) |> Base.encode16(case: :lower)

  @doc "Mint at Atlas, then mirror the key. The returned map carries the one-time `\"secret\"`."
  @spec mint(t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def mint(%__MODULE__{} = m, body, opts \\ []) do
    with {:ok, created} <- m.api.create(m.client, body, opts) do
      :ok = call(m, :put, [to_mirrored(created, hash_secret(created["secret"]))])
      {:ok, created}
    end
  end

  @doc """
  Rotate at Atlas, then mirror both sides: the successor is added, and the old key now ends at
  the end of the overlap (or is revoked at once when the overlap is 0).
  """
  @spec rotate(t(), String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def rotate(%__MODULE__{} = m, id, body \\ %{}, opts \\ []) do
    with {:ok, rotated} <- m.api.post_rotate(m.client, id, body, opts) do
      :ok = call(m, :put, [to_mirrored(rotated, hash_secret(rotated["secret"]))])

      if old = call(m, :get, [id]) do
        prev = rotated["previous_key"] || %{}

        if prev["revoked"] == true,
          do: call(m, :mark_revoked, [id, m.now.(), "rotated"]),
          else: call(m, :put, [%{old | expires_at: prev["expires_at"] || old.expires_at}])
      end

      {:ok, rotated}
    end
  end

  @doc """
  Import an existing key so customers keep their secret. `input` takes `:prefix` (required),
  one of `:secret`, `:secret_hash` (sha256 hex), `:bcrypt_hash` or `:argon2id_hash`, and any other
  create-key fields. A bcrypt/Argon2id key is verified at Atlas on first use (`:verify_at_atlas`).
  """
  @spec import_key(t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def import_key(%__MODULE__{} = m, input, opts \\ []) do
    {secret, input} = Map.pop(input, :secret)
    {secret_hash, input} = Map.pop(input, :secret_hash)
    {bcrypt, input} = Map.pop(input, :bcrypt_hash)
    {argon, input} = Map.pop(input, :argon2id_hash)
    {prefix, rest} = Map.pop(input, :prefix)
    legacy = bcrypt || argon
    hash = (secret_hash && String.downcase(secret_hash)) || (secret && hash_secret(secret))

    cond do
      legacy ->
        algo = if bcrypt, do: "bcrypt", else: "argon2id"
        body = Map.put(rest, :import, %{secret_hash: legacy, hash_algorithm: algo, prefix: prefix})

        with {:ok, imported} <- m.api.create(m.client, body, opts) do
          # No local sha256 yet; a retry that answered already_present keeps one the mirror learned.
          if imported["outcome"] != "already_present" or call(m, :get, [imported["id"]]) == nil,
            do: call(m, :put, [to_mirrored(imported, "legacy:" <> imported["id"])])

          {:ok, Map.put_new(imported, "outcome", "created")}
        end

      is_binary(hash) and Regex.match?(~r/^[0-9a-f]{64}$/, hash) ->
        body = Map.put(rest, :import, %{secret_hash: hash, hash_algorithm: "sha256_hex", prefix: prefix})

        with {:ok, imported} <- m.api.create(m.client, body, opts) do
          :ok = call(m, :put, [to_mirrored(imported, hash)])
          {:ok, Map.put_new(imported, "outcome", "created")}
        end

      true ->
        {:error, :secret_or_hash_required}
    end
  end

  @doc "Epoch ms of the last completed `sync/1`, or nil."
  @spec last_sync_at(t()) :: integer() | nil
  def last_sync_at(%__MODULE__{} = m), do: call(m, :get_last_sync_at, [])

  @doc """
  Revoke LOCALLY first (the key stops working here at once), then at Atlas. A key Atlas already
  revoked or no longer knows (404/409) counts as revoked; any other Atlas error is returned after
  the local revoke, so retry it.
  """
  @spec revoke(t(), String.t()) :: :ok | {:error, term()}
  def revoke(%__MODULE__{} = m, id) do
    :ok = call(m, :mark_revoked, [id, m.now.(), nil])

    case m.api.delete(m.client, id) do
      {:ok, _} -> :ok
      {:error, %{status: s}} when s in [404, 409] -> :ok
      {:error, e} -> {:error, e}
    end
  end

  @doc """
  Verify a presented secret against the mirror, with no network call. Options: `:required_scopes`,
  `:client_ip`. Returns `{:ok, %{key:, effective_scopes:, organization:, stale:}}` or `{:error, reason}`.
  """
  @spec verify(t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def verify(m, secret, opts \\ [])
  def verify(_m, secret, _opts) when not is_binary(secret) or secret == "", do: {:error, :invalid}

  def verify(%__MODULE__{} = m, secret, opts) do
    with {:ok, stale?} <- freshness(m) do
      hash = hash_secret(secret)

      key =
        call(m, :get_by_hash, [hash]) ||
          (m.opts[:verify_at_atlas] && verify_remote_miss(m, secret, hash, opts))

      with %{} <- key,
           true <- is_nil(key.revoked_at),
           true <- is_nil(key.expires_at) or key.expires_at > m.now.(),
           :ok <- check_ip(key, opts[:client_ip]),
           {:ok, effective, org} <- bound_scopes(m, key, secret, opts) do
        missing = Enum.reject(opts[:required_scopes] || [], &(&1 in effective))

        if missing == [] do
          result = %{key: key, effective_scopes: effective, organization: org, stale: stale?}
          {:ok, result}
        else
          {:error, {:insufficient_scope, missing}}
        end
      else
        {:error, reason} -> {:error, reason}
        _ -> {:error, :invalid}
      end
    end
  end

  # Returns {:ok, served_stale?} or {:error, {:stale, last_sync_at}}.
  defp freshness(%{opts: opts} = m) do
    case opts[:max_staleness_ms] do
      nil ->
        {:ok, false}

      max ->
        at = last_sync_at(m)
        behind = if at == nil, do: :infinity, else: m.now.() - at - max

        cond do
          behind != :infinity and behind <= 0 -> {:ok, false}
          at == nil or behind > Keyword.get(opts, :serve_stale_for_ms, 0) -> {:error, {:stale, at}}
          true ->
            if cb = opts[:on_serve_stale], do: cb.(%{last_sync_at: at, stale_for_ms: behind})
            {:ok, true}
        end
    end
  end

  defp verify_remote_miss(m, secret, hash, opts) do
    with {:ok, %{"valid" => true, "id" => id}} <- m.api.post_verify(m.client, remote_body(secret, opts)),
         {:ok, full} <- m.api.get(m.client, id) do
      key = to_mirrored(full, hash)
      :ok = call(m, :put, [key])
      key
    else
      _ -> nil
    end
  end

  defp remote_body(secret, opts) do
    base = %{secret: secret}
    if opts[:client_ip], do: Map.put(base, :client_ip, opts[:client_ip]), else: base
  end

  defp check_ip(%{allowed_ips: ips}, client_ip) when is_list(ips) and ips != [] do
    cond do
      is_nil(client_ip) -> {:error, :client_ip_required}
      ip_in_allowlist?(client_ip, ips) -> :ok
      true -> {:error, :ip_not_allowed}
    end
  end

  defp check_ip(_key, _ip), do: :ok

  defp bound_scopes(m, key, secret, opts) do
    effective = expand(key.scopes || [], m.implications, m.allowed)

    if key.subject_type == "user" and key.organization_id do
      # A bound key stands for the user's CURRENT membership; never answer from the key's own scopes.
      cond do
        fun = m.opts[:membership] ->
          case fun.(key.subject_id, key.organization_id) do
            nil -> {:error, :invalid}
            held -> {:ok, intersect_scopes(effective, held["permissions"] || []), held}
          end

        true ->
          case m.api.post_verify(m.client, remote_body(secret, opts)) do
            {:ok, %{"valid" => true, "organization" => org} = r} when is_map(org) -> {:ok, r["effective_scopes"] || [], org}
            {:ok, _} -> {:error, :invalid}
            {:error, _} -> {:error, :membership_unresolved}
          end
      end
    else
      {:ok, effective, nil}
    end
  end

  @doc "Whether a permission covers a key scope: same name, `*`, or `<prefix>:*`. Mirrors Atlas verify."
  @spec permission_covers_scope?(String.t(), String.t()) :: boolean()
  def permission_covers_scope?(permission, scope) do
    permission == scope or permission == "*" or
      (String.ends_with?(permission, ":*") and String.starts_with?(scope, String.slice(permission, 0..-2//1)))
  end

  @doc "The key scopes a membership's permissions cover (Atlas's `effective_scopes` for a bound key), sorted."
  @spec intersect_scopes([String.t()], [String.t()]) :: [String.t()]
  def intersect_scopes(scopes, permissions) do
    scopes
    |> Enum.filter(fn s -> Enum.any?(permissions, &permission_covers_scope?(&1, s)) end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp expand(held, implications, allowed) do
    vocab =
      Enum.reduce(implications, MapSet.new(allowed), fn {from, tos}, acc ->
        Enum.reduce(tos, MapSet.put(acc, from), fn t, a -> if t == "*", do: a, else: MapSet.put(a, t) end)
      end)

    walk(held, MapSet.new(held), implications, vocab) |> Enum.sort()
  end

  defp walk([], out, _imp, _vocab), do: out

  defp walk([s | queue], out, imp, vocab) do
    {out, queue} =
      Enum.reduce(Map.get(imp, s, []), {out, queue}, fn to, acc ->
        targets = if to == "*", do: MapSet.to_list(vocab), else: [to]

        Enum.reduce(targets, acc, fn t, {o, q} ->
          if MapSet.member?(o, t), do: {o, q}, else: {MapSet.put(o, t), [t | q]}
        end)
      end)

    walk(queue, out, imp, vocab)
  end

  @doc "Whether `ip` is inside one of the addresses / CIDR ranges. Unparseable input is never inside."
  @spec ip_in_allowlist?(String.t(), [String.t()]) :: boolean()
  def ip_in_allowlist?(ip, cidrs) do
    case parse_ip(ip) do
      nil -> false
      {addr, width} -> Enum.any?(cidrs, &cidr_match?(&1, addr, width))
    end
  end

  defp cidr_match?(entry, addr, width) do
    [base | rest] = String.split(String.trim(entry), "/", parts: 2)

    with {net, ^width} <- parse_ip(base),
         {:ok, bits} <- parse_bits(rest, width) do
      shift = width - bits
      addr >>> shift == net >>> shift
    else
      _ -> false
    end
  end

  defp parse_bits([], width), do: {:ok, width}

  defp parse_bits([text], width) do
    case Integer.parse(text) do
      {n, ""} when n >= 0 and n <= width -> {:ok, n}
      _ -> :error
    end
  end

  defp parse_ip(text) do
    case :inet.parse_strict_address(String.to_charlist(String.trim(text))) do
      {:ok, {a, b, c, d}} -> {a <<< 24 ||| b <<< 16 ||| c <<< 8 ||| d, 32}
      {:ok, t} when tuple_size(t) == 8 -> {t |> Tuple.to_list() |> Enum.reduce(0, fn g, acc -> acc <<< 16 ||| g end), 128}
      _ -> nil
    end
  end

  defp to_mirrored(key, hash) do
    %{
      id: key["id"],
      hash: hash,
      prefix: key["prefix"],
      subject_type: key["subject_type"],
      subject_id: key["subject_id"],
      name: key["name"],
      scopes: key["scopes"],
      allowed_ips: key["allowed_ips"],
      expires_at: key["expires_at"],
      revoked_at: key["revoked_at"],
      organization_id: key["organization_id"],
      revoked_reason: key["revoked_reason"]
    }
  end

  @doc """
  Consume the revocation feed from the stored cursor, revoking each listed key locally. Call it on a
  timer (every few seconds to a minute). Returns `{:ok, %{revoked: n}}`.
  """
  @spec sync(t()) :: {:ok, %{revoked: non_neg_integer()}} | {:error, term()}
  def sync(%__MODULE__{} = m), do: sync_pages(m, call(m, :get_cursor, []), 0)

  defp sync_pages(m, since, revoked) do
    params = [limit: 100] ++ if(since, do: [since: since], else: [])

    with {:ok, page} <- m.api.get_revoked(m.client, params: params) do
      refs = page["data"] || []

      for ref <- refs,
          do: call(m, :mark_revoked, [ref["id"], ref["revoked_at"] || m.now.(), ref["revoked_reason"]])

      revoked = revoked + length(refs)
      next = page["next_cursor"]
      if is_binary(next), do: call(m, :set_cursor, [next])

      if page["has_more"] == true and is_binary(next) do
        sync_pages(m, next, revoked)
      else
        call(m, :set_last_sync_at, [m.now.()])
        {:ok, %{revoked: revoked}}
      end
    end
  end

  @doc """
  Apply a VERIFIED `api_key.*` (or `organization_membership.deleted`) webhook event map
  (`%{"type" => ..., "data" => ...}`). Returns whether the event changed the mirror.
  """
  @spec apply_webhook(t(), map()) :: boolean()
  def apply_webhook(%__MODULE__{} = m, %{"type" => type, "data" => data}) when is_binary(type) and is_map(data) do
    cond do
      type in ["organization_membership.deleted", "organizationMembership.deleted"] ->
        with u when is_binary(u) <- data["user_id"],
             o when is_binary(o) <- data["organization_id"] do
          call(m, :mark_membership_ended, [u, o, m.now.()])
          true
        else
          _ -> false
        end

      String.starts_with?(type, "api_key.") and is_binary(data["id"]) ->
        apply_key_event(m, type, data, call(m, :get, [data["id"]]))

      true ->
        false
    end
  end

  def apply_webhook(_m, _event), do: false

  defp apply_key_event(_m, _type, _data, nil), do: false

  defp apply_key_event(m, "api_key.restored", data, held) do
    if is_nil(held.revoked_at) do
      false
    else
      call(m, :put, [%{held | revoked_at: nil, revoked_reason: nil, expires_at: pick(data, "expires_at", held.expires_at)}])
      true
    end
  end

  defp apply_key_event(m, type, data, held) do
    cond do
      type == "api_key.revoked" or (is_integer(data["revoked_at"]) and is_nil(held.revoked_at)) ->
        call(m, :mark_revoked, [held.id, if(is_integer(data["revoked_at"]), do: data["revoked_at"], else: m.now.()), data["revoked_reason"]])
        true

      type in ["api_key.updated", "api_key.created"] ->
        call(m, :put, [
          %{
            held
            | name: pick(data, "name", held.name),
              scopes: pick(data, "scopes", held.scopes),
              allowed_ips: pick(data, "allowed_ips", held.allowed_ips),
              expires_at: pick(data, "expires_at", held.expires_at)
          }
        ])

        true

      true ->
        false
    end
  end

  defp pick(data, field, default), do: if(Map.has_key?(data, field), do: data[field], else: default)

  defp call(%__MODULE__{store: {mod, ref}}, fun, args), do: apply(mod, fun, [ref | args])
end
