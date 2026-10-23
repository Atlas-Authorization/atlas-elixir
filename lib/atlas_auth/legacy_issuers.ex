defmodule AtlasAuth.LegacyIssuers do
  @moduledoc """
  Accepting your OLD auth provider's JWTs during a cutover — today, Better Auth's
  `jwt` plugin tokens.

  When you move to Atlas, API clients may still hold short-lived JWTs your Better
  Auth app minted. Pass `:legacy_issuers` to `AtlasAuth.Verifier.verify/2` (and so to
  `AtlasAuth.Plug`): a token whose `iss` is one of these issuers is verified against
  THAT issuer's key set (the JWKS you imported into Atlas, or the old app's
  `/api/auth/jwks`) for a bounded window, and its `sub` (the Better Auth user id) is
  mapped to the Atlas user id — Atlas keeps the Better Auth id as the user's
  `external_id`. After `:until`, those tokens are refused like any other foreign
  token. Atlas tokens are unaffected.

      AtlasAuth.Verifier.verify(token,
        issuer: "https://inst.atlas.example",
        jwks_url: "https://inst.atlas.example/.well-known/jwks.json",
        secret_key: System.fetch_env!("ATLAS_SECRET_KEY"),
        legacy_issuers: [
          [issuer: "https://app.example.com", until: ~U[2026-12-31 00:00:00Z],
           jwks_url: "https://app.example.com/api/auth/jwks"]
        ]
      )

  Each entry (a keyword list or map):

    * `:issuer` — the `iss` the old tokens carry (Better Auth: its `baseURL`, unless
      `jwt.issuer` was set). It may not be the Atlas issuer.
    * `:until` — end of the window: a `DateTime`, epoch milliseconds, or an ISO-8601
      string. Required: a legacy issuer is never accepted forever.
    * `:jwks` (a key list or `%{"keys" => [...]}`) or `:jwks_url` — exactly one.
    * `:audience` — a string or list; when set, `aud` must contain one of them.
    * `:algorithms` — default Better Auth's: EdDSA, ES256, ES512, RS256, PS256.
    * `:resolve_subject` — `fn legacy_sub, claims -> atlas_user_id | nil end`.
      Default: look the user up by `external_id` through the Backend API with the
      verifier's `:secret_key` (`:api_url`, default `https://api.atlasauth.net`),
      cached for five minutes in a node-local ETS table. `nil` refuses the token.

  Verified claims carry `sub` = the Atlas id, `external_id` = the old id and
  `legacy` = `%{"kind" => "better_auth", "issuer" => ..., "sub" => ...}` (in
  `claims.raw`). A legacy token without `exp` is refused.
  """
  use GenServer

  alias AtlasAuth.JWKSCache

  @table :atlas_auth_legacy_subjects
  @algs ["EdDSA", "ES256", "ES512", "RS256", "PS256"]
  @subject_ttl_ms 5 * 60_000
  @subject_cache_max 10_000
  @default_api_url "https://api.atlasauth.net"

  @doc "Better Auth's `jwt` plugin algorithms (the default `:algorithms`)."
  def algorithms, do: @algs

  @doc "How long a resolved `sub` → Atlas id mapping is reused (ms)."
  def subject_ttl_ms, do: @subject_ttl_ms

  @doc false
  def start_link(_ \\ []), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl GenServer
  def init(nil) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    {:ok, nil}
  end

  @doc false
  def clear_subjects, do: :ets.delete_all_objects(@table)

  @doc """
  Route and verify `token` against the configured legacy issuers.

  Returns `:skip` when the token is not from a legacy issuer inside its window (the
  caller verifies it as an Atlas token), else `{:ok, claims_map}` or
  `{:error, :invalid | :no_keys}`. Raises `ArgumentError` on a misconfigured entry.
  """
  @spec verify(String.t(), [keyword() | map()], keyword()) ::
          :skip | {:ok, map()} | {:error, :invalid | :no_keys}
  def verify(token, entries, opts) do
    atlas_issuer = opts[:issuer]
    now_ms = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    entries = Enum.map(entries || [], &normalize!(&1, atlas_issuer, opts))

    case peek_issuer(token) do
      nil ->
        :skip

      iss ->
        case Enum.find(entries, &(&1.issuer == iss)) do
          %{until_ms: until} = entry when until > now_ms ->
            verify_entry(token, entry, opts, now_ms)

          _ ->
            :skip
        end
    end
  end

  defp normalize!(entry, atlas_issuer, opts) do
    get = fn key -> if is_map(entry), do: Map.get(entry, key), else: Keyword.get(entry, key) end
    issuer = get.(:issuer)

    if issuer in [nil, ""],
      do: raise(ArgumentError, "legacy_issuers: every entry needs `:issuer`.")

    if issuer == atlas_issuer,
      do:
        raise(ArgumentError, "legacy_issuers: a legacy issuer cannot be the Atlas issuer itself.")

    until_ms = until_ms(get.(:until))

    if until_ms == 0,
      do:
        raise(
          ArgumentError,
          "legacy_issuers: \"#{issuer}\" needs a valid `:until` (the end of the window)."
        )

    jwks = get.(:jwks)
    jwks_url = get.(:jwks_url)

    if jwks_url in [nil, ""] == is_nil(jwks),
      do:
        raise(
          ArgumentError,
          "legacy_issuers: \"#{issuer}\" needs exactly one of `:jwks` or `:jwks_url`."
        )

    resolver = get.(:resolve_subject)

    if is_nil(resolver) and opts[:secret_key] in [nil, ""] do
      raise ArgumentError,
            "legacy_issuers: \"#{issuer}\" maps its `sub` to an Atlas user through the Backend API, " <>
              "which needs `:secret_key` on the verifier — or give the issuer a `:resolve_subject`."
    end

    %{
      issuer: issuer,
      until_ms: until_ms,
      jwks: jwks,
      jwks_url: jwks_url,
      audience: List.wrap(get.(:audience)),
      algorithms: get.(:algorithms) || @algs,
      resolve_subject: resolver,
      kind: get.(:kind) || "better_auth"
    }
  end

  @doc "The window end in epoch ms (0 when unparseable)."
  def until_ms(%DateTime{} = dt), do: DateTime.to_unix(dt, :millisecond)
  def until_ms(n) when is_integer(n) and n > 0, do: n
  def until_ms(n) when is_float(n) and n > 0, do: trunc(n)

  def until_ms(s) when is_binary(s) do
    case DateTime.from_iso8601(String.trim(s)) do
      {:ok, dt, _offset} -> DateTime.to_unix(dt, :millisecond)
      _ -> 0
    end
  end

  def until_ms(_), do: 0

  @doc "The UNVERIFIED `iss` of a compact JWT, for routing only."
  def peek_issuer(token) when is_binary(token) do
    with [_h, payload, _s] <- String.split(token, "."),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, %{"iss" => iss}} when is_binary(iss) <- Jason.decode(json) do
      iss
    else
      _ -> nil
    end
  end

  def peek_issuer(_), do: nil

  defp verify_entry(token, entry, opts, now_ms) do
    [header_b64 | _] = String.split(token, ".")

    with {:ok, header} <- decode_header(header_b64),
         {:ok, alg} <- allowed_alg(header, entry),
         {:ok, keys} <- keys(entry, header["kid"], opts, now_ms),
         {:ok, payload} <- verify_with(keys, header["kid"], alg, token),
         :ok <- check_claims(payload, entry, div(now_ms, 1000), Keyword.get(opts, :leeway, 5)),
         {:ok, legacy_sub} <- legacy_sub(payload),
         {:ok, atlas_id} <- resolve(legacy_sub, payload, entry, opts, now_ms) do
      {:ok,
       payload
       |> Map.put("sub", atlas_id)
       |> Map.put("external_id", legacy_sub)
       |> Map.put("legacy", %{"kind" => entry.kind, "issuer" => entry.issuer, "sub" => legacy_sub})}
    end
  end

  defp decode_header(b64) do
    with {:ok, json} <- Base.url_decode64(b64, padding: false),
         {:ok, map} when is_map(map) <- Jason.decode(json) do
      {:ok, map}
    else
      _ -> {:error, :invalid}
    end
  end

  defp allowed_alg(%{"alg" => alg}, entry) when is_binary(alg) do
    if alg in entry.algorithms and alg in @algs, do: {:ok, alg}, else: {:error, :invalid}
  end

  defp allowed_alg(_, _), do: {:error, :invalid}

  defp keys(%{jwks: jwks}, _kid, _opts, _now) when not is_nil(jwks) do
    list = if is_map(jwks), do: Map.get(jwks, "keys") || Map.get(jwks, :keys) || [], else: jwks
    if is_list(list) and list != [], do: {:ok, list}, else: {:error, :no_keys}
  end

  defp keys(%{jwks_url: url}, kid, opts, now_ms) do
    cache = Keyword.get(opts, :cache, JWKSCache)

    fetcher =
      Keyword.get(opts, :legacy_fetcher) ||
        Keyword.get(opts, :fetcher, &AtlasAuth.Verifier.default_fetch/1)

    case JWKSCache.get(cache, url, kid, fetcher, now_ms) do
      {keys, _} when is_list(keys) and keys != [] -> {:ok, keys}
      _ -> {:error, :no_keys}
    end
  end

  # The algorithms a JWK's type can verify.
  defp key_algs(%{"kty" => "RSA"}), do: ["RS256", "PS256"]
  defp key_algs(%{"kty" => "EC", "crv" => "P-256"}), do: ["ES256"]
  defp key_algs(%{"kty" => "EC", "crv" => "P-521"}), do: ["ES512"]
  defp key_algs(%{"kty" => "OKP", "crv" => "Ed25519"}), do: ["EdDSA"]
  defp key_algs(_), do: []

  defp verify_with(keys, kid, alg, token) do
    keys
    |> Enum.filter(fn k ->
      is_map(k) and (kid in [nil, ""] or k["kid"] == kid) and alg in key_algs(k) and
        k["alg"] in [nil, alg]
    end)
    |> Enum.find_value({:error, :invalid}, fn k ->
      try do
        case JOSE.JWT.verify_strict(JOSE.JWK.from_map(k), [alg], token) do
          {true, %JOSE.JWT{fields: claims}, _} when is_map(claims) -> {:ok, claims}
          _ -> nil
        end
      rescue
        _ -> nil
      end
    end)
  end

  defp check_claims(claims, entry, now_sec, leeway) do
    exp = num(claims["exp"])
    nbf = num(claims["nbf"])
    iat = num(claims["iat"])

    cond do
      claims["iss"] != entry.issuer -> {:error, :invalid}
      # A legacy token without an expiry would outlive the window it is accepted in.
      exp == nil -> {:error, :invalid}
      now_sec > exp + leeway -> {:error, :invalid}
      nbf != nil and now_sec + leeway < nbf -> {:error, :invalid}
      iat != nil and iat - leeway > now_sec -> {:error, :invalid}
      not audience_ok?(claims["aud"], entry.audience) -> {:error, :invalid}
      true -> :ok
    end
  end

  defp audience_ok?(_aud, []), do: true
  defp audience_ok?(aud, wanted) when is_binary(aud), do: aud in wanted
  defp audience_ok?(aud, wanted) when is_list(aud), do: Enum.any?(aud, &(&1 in wanted))
  defp audience_ok?(_aud, _wanted), do: false

  defp legacy_sub(%{"sub" => sub}) when is_binary(sub) and sub != "", do: {:ok, sub}
  defp legacy_sub(%{"id" => id}) when is_binary(id) and id != "", do: {:ok, id}
  defp legacy_sub(_), do: {:error, :invalid}

  defp resolve(legacy_sub, claims, %{resolve_subject: f}, _opts, _now) when is_function(f, 2) do
    case safe(fn -> f.(legacy_sub, claims) end) do
      id when is_binary(id) and id != "" -> {:ok, id}
      _ -> {:error, :invalid}
    end
  end

  defp resolve(legacy_sub, _claims, entry, opts, now_ms) do
    key = {entry.issuer, legacy_sub}

    cached =
      case :ets.lookup(@table, key) do
        [{^key, id, at}] when now_ms - at < @subject_ttl_ms -> {:hit, id}
        _ -> :miss
      end

    id =
      case cached do
        {:hit, id} -> id
        :miss -> lookup(key, legacy_sub, opts, now_ms)
      end

    if is_binary(id) and id != "", do: {:ok, id}, else: {:error, :invalid}
  end

  defp lookup(key, legacy_sub, opts, now_ms) do
    base = opts |> Keyword.get(:api_url, @default_api_url) |> String.trim_trailing("/")
    query = URI.encode_query(%{"external_id" => legacy_sub, "limit" => "1"})
    getter = Keyword.get(opts, :getter, &default_get/2)

    headers = [
      {"authorization", "Bearer " <> opts[:secret_key]},
      {"accept", "application/json"}
    ]

    case safe(fn -> getter.(base <> "/v1/users?" <> query, headers) end) do
      {:ok, status, body} when status in 200..299 ->
        id =
          case Jason.decode(body) do
            {:ok, %{"data" => [%{"id" => id} | _]}} when is_binary(id) and id != "" -> id
            _ -> nil
          end

        if :ets.info(@table, :size) >= @subject_cache_max, do: :ets.delete_all_objects(@table)
        :ets.insert(@table, {key, id, now_ms})
        id

      # Not cached: a transient failure should not stick.
      _ ->
        nil
    end
  end

  defp safe(fun) do
    fun.()
  rescue
    _ -> nil
  end

  defp num(n) when is_integer(n), do: n
  defp num(n) when is_float(n), do: trunc(n)
  defp num(_), do: nil

  @doc false
  def default_get(url, headers) do
    _ = :inets.start()
    _ = :ssl.start()
    hs = Enum.map(headers, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)
    http_opts = [{:timeout, 10_000}, {:connect_timeout, 5_000}]

    case :httpc.request(:get, {String.to_charlist(url), hs}, http_opts, [{:body_format, :binary}]) do
      {:ok, {{_v, status, _r}, _h, body}} -> {:ok, status, body}
      {:error, reason} -> {:error, reason}
    end
  end
end
