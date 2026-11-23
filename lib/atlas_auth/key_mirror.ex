defmodule AtlasAuth.KeyMirror.Store do
  @moduledoc """
  What `AtlasAuth.KeyMirror` needs from storage: put / get / get-by-hash / mark-revoked,
  the revocation-feed cursor and the last completed sync time. A store is a
  `{module, ref}` pair; every callback receives `ref` first.

  A mirrored key is a map with the keys `:id`, `:hash` (sha256 of the secret, lowercase
  hex; never the secret), `:prefix`, `:subject_type`, `:subject_id`, `:name`, `:scopes`,
  `:allowed_ips`, `:expires_at` (epoch ms or nil), `:revoked_at` (epoch ms or nil),
  `:organization_id`, `:revoked_reason`, and (optional, absent = a secret key that is enabled) `:enabled`
  (`false` = refused like an unknown key), `:credential` (`"secret"` or `"key_pair"`; a key-pair row has
  no secret, its `:hash` is a placeholder nothing matches), `:public_key_pem`, `:audience`,
  `:max_token_lifetime_seconds`.

  A store may also implement `claim_assertion_jti/4` to share used assertion ids across nodes.
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
  @doc "Record an assertion `jti` as used until `expires_at_ms`; `false` when it was already used (a replay)."
  @callback claim_assertion_jti(ref :: term(), key_id :: String.t(), jti :: String.t(), expires_at_ms :: integer()) :: boolean()
  @optional_callbacks claim_assertion_jti: 4
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

  `verify_assertion/3` verifies a key-pair assertion (`AtlasAuth.ApiKeyAssertion.sign/4`) the same way and
  adds the errors `:invalid_assertion`, `:assertion_expired`, `:assertion_not_yet_valid`, `:wrong_audience`,
  `:assertion_lifetime_too_long`, `:assertion_replayed` and `{:scope_not_granted, missing}`.
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
      :ok = call(m, :put, [to_mirrored(created, row_hash(created))])
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
      :ok = call(m, :put, [to_mirrored(rotated, row_hash(rotated))])

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
           true <- is_nil(key.revoked_at) and Map.get(key, :enabled) != false,
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

  @doc """
  Verify a key-pair assertion locally with the checks Atlas verify makes: the signature with the stored
  public key (`alg` must fit its type), `iss` = `kid`, `aud`, `iat`, `exp` and the lifetime cap, `nbf`, `scope`
  (a subset of the key's, narrows the result), revocation, expiry, the IP allowlist, then the single-use `jti`.
  Options: `:required_scopes`, `:client_ip`. Returns `{:ok, %{key:, effective_scopes:, organization:, stale:,
  credential: "key_pair", jti:, exp:}}` or `{:error, code}`; a key the mirror does not hold is `{:error, :invalid}`.
  The `jti` is claimed through the store's optional `claim_assertion_jti/4`, else in this node's memory, and only
  after every other check passed.
  """
  @spec verify_assertion(t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def verify_assertion(m, token, opts \\ [])
  def verify_assertion(_m, token, _opts) when not is_binary(token), do: {:error, :invalid_assertion}

  def verify_assertion(%__MODULE__{} = m, token, opts) do
    with {:ok, stale?} <- freshness(m),
         {:ok, header, claims} <- parse_assertion(token),
         kid when is_binary(kid) and kid != "" <- header["kid"] || {:error, :invalid_assertion},
         %{} = key <- call(m, :get, [kid]) || {:error, :invalid},
         :ok <- assertion_key_ok(key, header, claims, token, kid),
         true <- (is_nil(key.revoked_at) and (is_nil(key.expires_at) or key.expires_at > m.now.())) || {:error, :invalid},
         now_s = div(m.now.(), 1000),
         :ok <- check_claims(key, claims, now_s),
         :ok <- check_ip(key, opts[:client_ip]),
         {:ok, effective, org} <- assertion_scopes(m, key, claims["scope"], opts),
         :ok <- claim_jti(m, key, claims) do
      {:ok, %{key: key, effective_scopes: effective, organization: org, stale: stale?, credential: "key_pair", jti: claims["jti"], exp: claims["exp"]}}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_assertion}
    end
  end

  defp parse_assertion(token) do
    with [_, _, _] <- String.split(token, "."),
         {_, %{} = header} <- {:h, peek(fn -> JOSE.JWS.peek_protected(token) end)},
         {_, %{} = claims} <- {:c, peek(fn -> JOSE.JWT.peek_payload(token).fields end)} do
      {:ok, header, claims}
    else
      _ -> {:error, :invalid_assertion}
    end
  end

  defp peek(fun) do
    case fun.() do
      json when is_binary(json) -> Jason.decode!(json)
      %{} = map -> map
    end
  rescue
    _ -> nil
  end

  # Signature (alg pinned to the stored key's type), iss = kid, then the disabled row.
  defp assertion_key_ok(key, header, claims, token, kid) do
    pem = Map.get(key, :public_key_pem)

    with true <- Map.get(key, :credential) == "key_pair" and is_binary(pem) and pem != "",
         alg when alg in ["ES256", "EdDSA"] <- header["alg"],
         true <- signature_ok?(pem, alg, token),
         true <- claims["iss"] == kid,
         true <- Map.get(key, :enabled) != false do
      :ok
    else
      _ -> {:error, :invalid_assertion}
    end
  end

  defp signature_ok?(pem, alg, token) do
    jwk = JOSE.JWK.from_pem(pem)

    kty_ok =
      case {alg, JOSE.JWK.to_map(jwk)} do
        {"ES256", {_, %{"kty" => "EC", "crv" => "P-256"}}} -> true
        {"EdDSA", {_, %{"kty" => "OKP", "crv" => "Ed25519"}}} -> true
        _ -> false
      end

    kty_ok and match?({true, _, _}, JOSE.JWT.verify_strict(jwk, [alg], token))
  rescue
    _ -> false
  end

  defp check_claims(key, claims, now_s) do
    aud = claims["aud"]
    {iat, exp, nbf} = {claims["iat"], claims["exp"], claims["nbf"]}
    max = min(Map.get(key, :max_token_lifetime_seconds) || 3600, 86_400)

    cond do
      not ((is_binary(aud) and aud == Map.get(key, :audience)) or (is_list(aud) and Map.get(key, :audience) in aud)) -> {:error, :wrong_audience}
      not is_number(iat) or not is_number(exp) -> {:error, :invalid_assertion}
      Map.has_key?(claims, "nbf") and not is_number(nbf) -> {:error, :invalid_assertion}
      Map.has_key?(claims, "jti") and not (is_binary(claims["jti"]) and claims["jti"] != "") -> {:error, :invalid_assertion}
      Map.has_key?(claims, "scope") and not is_binary(claims["scope"]) -> {:error, :invalid_assertion}
      iat > now_s + 60 or (is_number(nbf) and nbf > now_s + 60) -> {:error, :assertion_not_yet_valid}
      exp <= now_s - 30 -> {:error, :assertion_expired}
      exp - iat > max -> {:error, :assertion_lifetime_too_long}
      true -> :ok
    end
  end

  defp assertion_scopes(m, key, scope, opts) do
    effective = expand(key.scopes || [], m.implications, m.allowed)

    with {:ok, effective, org} <- assertion_membership(m, key, effective),
         {:ok, effective} <- narrow(effective, scope) do
      missing = Enum.reject(opts[:required_scopes] || [], &(&1 in effective))
      if missing == [], do: {:ok, effective, org}, else: {:error, {:insufficient_scope, missing}}
    end
  end

  defp assertion_membership(m, key, effective) do
    if key.subject_type == "user" and key.organization_id do
      case m.opts[:membership] do
        nil ->
          {:error, :membership_unresolved}

        fun ->
          case fun.(key.subject_id, key.organization_id) do
            nil -> {:error, :invalid}
            held -> {:ok, intersect_scopes(effective, held["permissions"] || []), held}
          end
      end
    else
      {:ok, effective, nil}
    end
  end

  defp narrow(effective, scope) when is_binary(scope) do
    case String.split(scope) do
      [] ->
        {:ok, effective}

      asked ->
        case Enum.reject(asked, &(&1 in effective)) do
          [] -> {:ok, Enum.filter(effective, &(&1 in asked))}
          missing -> {:error, {:scope_not_granted, missing}}
        end
    end
  end

  defp narrow(effective, _), do: {:ok, effective}

  # Last, so a refused assertion never burns its jti.
  defp claim_jti(m, key, %{"jti" => jti, "exp" => exp}) when is_binary(jti) do
    until = trunc(exp * 1000)
    {mod, ref} = m.store

    first? =
      if function_exported?(mod, :claim_assertion_jti, 4) do
        mod.claim_assertion_jti(ref, key.id, jti, until)
      else
        AtlasAuth.DPoP.MemoryReplayStore.claim("key_pair:" <> key.id <> "\n" <> jti, until, m.now.())
      end

    if first?, do: :ok, else: {:error, :assertion_replayed}
  end

  defp claim_jti(_m, _key, _claims), do: :ok

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
      revoked_reason: key["revoked_reason"],
      enabled: key["enabled"],
      credential: key["credential"] || "secret",
      public_key_pem: key["public_key"],
      audience: key["audience"],
      max_token_lifetime_seconds: key["max_token_lifetime_seconds"]
    }
  end

  # The secret's sha256; a key-pair key has no secret, so its row carries a placeholder nothing can match.
  defp row_hash(%{"secret" => secret}) when is_binary(secret) and secret != "", do: hash_secret(secret)
  defp row_hash(%{"id" => id}), do: "key_pair:" <> id

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
          |> Map.put(:enabled, pick(data, "enabled", Map.get(held, :enabled)))
        ])

        true

      true ->
        false
    end
  end

  defp pick(data, field, default), do: if(Map.has_key?(data, field), do: data[field], else: default)

  defp call(%__MODULE__{store: {mod, ref}}, fun, args), do: apply(mod, fun, [ref | args])
end
