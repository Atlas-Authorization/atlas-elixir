defmodule AtlasAuth.Verifier do
  @moduledoc """
  Local RS256 verification of Atlas session JWTs — the Elixir port of the Go
  (`verify.go`) and PHP (`SessionVerifier`) verifiers, with the same rules.

  WHY this verifies locally and never calls Atlas on the hot path: a customer API
  handling thousands of requests a second cannot make an outbound call to verify
  each one, and a verifier that did would make Atlas's availability the
  customer's availability. So the default path is a signature check against the
  cached JWKS (`AtlasAuth.JWKSCache`), and the revocation window is bounded
  instead by the short token lifetime.

  The checks, in order — matching the other SDKs exactly:

    * shape — a non-empty, three-part JWT, else `:malformed`;
    * algorithm — the header `alg` must be `"RS256"`. Pinning the algorithm is
      what stops an `alg: none` token, or one that coerces the RSA public key
      into an HMAC secret, from ever verifying;
    * signature — RS256 against the JWKS key whose `kid` matches the header;
    * `iss` — must equal the configured issuer. An unchecked issuer would accept
      *any* Atlas instance's tokens, so a missing issuer is a config error, not a
      soft default;
    * `exp` / `nbf` / `iat` — with ~5s of clock skew either side, matching the
      server's minting tolerance;
    * the §13.1 token-confusion guard — an Atlas OP access token (`token_use:
      "access"`/`"access_token"`) and an id_token (which carries `aud`) are signed
      with the *same* per-instance RS256 key as a first-party session JWT. Reject
      any token carrying an OP marker so a "Sign in with Atlas" relying party
      cannot replay one as a customer session. An *absent* `token_use`/`aud` is a
      valid session (backward-compat), so this never mass-invalidates a live
      fleet;
    * `azp` — when `:authorized_parties` is set, the token's authorized party must
      be in the allowlist, else `:unauthorized_party`.

  WHY failure reasons are coarse: telling a caller whether the signature, the
  issuer or the expiry was the thing that was wrong helps someone refining a
  forged token far more than it helps a developer debugging a real one. The
  reasons are `:malformed`, `:invalid`, `:no_keys`, and `:unauthorized_party`.

  ## Options

  Pass as a keyword list to `verify/2` and `authenticate_request/2`, or set
  application env / environment variables for the two required values:

    * `:jwks_url` — the instance JWKS URL. Falls back to
      `Application.get_env(:atlas_auth, :jwks_url)` then `ATLAS_JWKS_URL`.
    * `:issuer` — the expected `iss`. Falls back to
      `Application.get_env(:atlas_auth, :issuer)` then `ATLAS_ISSUER`.
    * `:authorized_parties` — optional `azp` allowlist (list of strings).
    * `:leeway` — clock-skew tolerance in seconds (default `5`).
    * `:fetcher` — a `(url -> {:ok, [key_map]} | {:error, term})` function. The
      default fetches over HTTP with `:httpc` (no extra dependency). Inject your
      own to avoid the network entirely, as the tests do.
    * `:cache` — the `AtlasAuth.JWKSCache` server (default the app-started one).
    * `:now_ms` — clock override in milliseconds, for tests.
  """

  alias AtlasAuth.{Claims, JWKSCache}

  @clock_skew_seconds 5

  @type reason :: :malformed | :invalid | :no_keys | :unauthorized_party
  @type result :: {:ok, Claims.t()} | {:error, reason()}

  @doc """
  Verify a session token. Returns `{:ok, %AtlasAuth.Claims{}}` or
  `{:error, reason}`.
  """
  @spec verify(String.t() | nil, keyword()) :: result()
  def verify(token, opts \\ [])

  def verify(token, _opts) when token in [nil, ""], do: {:error, :malformed}

  def verify(token, opts) when is_binary(token) do
    parts = String.split(token, ".")

    if length(parts) != 3 do
      {:error, :malformed}
    else
      do_verify(token, parts, opts)
    end
  end

  @doc """
  Verify whatever a request carries. A `Authorization: Bearer <jwt>` header wins
  over a `__session` cookie — a caller that set the header deliberately should
  not be overridden by a stale cookie.

  `headers` may be a `Plug.Conn`-style list of `{name, value}` tuples (names
  lower-cased, as Plug delivers them) or a map of header name to value.
  """
  @spec authenticate_request(list() | map(), keyword()) :: result()
  def authenticate_request(headers, opts \\ []) do
    bearer =
      case header(headers, "authorization") do
        "Bearer " <> rest -> rest
        _ -> nil
      end

    token = bearer || cookie(header(headers, "cookie"), "__session")

    case token do
      nil -> {:error, :malformed}
      "" -> {:error, :malformed}
      t -> verify(t, opts)
    end
  end

  # --- internals -----------------------------------------------------------

  defp do_verify(token, [header_b64, _payload_b64, _sig_b64] = _parts, opts) do
    jwks_url = required(opts, :jwks_url, "ATLAS_JWKS_URL")
    issuer = required(opts, :issuer, "ATLAS_ISSUER")
    authorized_parties = Keyword.get(opts, :authorized_parties, [])
    leeway = Keyword.get(opts, :leeway, @clock_skew_seconds)
    now_ms = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    cache = Keyword.get(opts, :cache, JWKSCache)
    fetcher = Keyword.get(opts, :fetcher, &default_fetch/1)

    header = decode_header(header_b64)
    kid = header && header["kid"]

    with :ok <- check_alg(header),
         {keys, _outcome} when is_list(keys) and keys != [] <-
           JWKSCache.get(cache, jwks_url, kid, fetcher, now_ms),
         {:ok, key_map} <- select_key(keys, kid),
         {:ok, claims} <- verify_signature(key_map, token),
         :ok <- check_issuer(claims, issuer),
         :ok <- check_time(claims, div(now_ms, 1000), leeway),
         :ok <- check_token_confusion(claims),
         :ok <- check_azp(claims, authorized_parties) do
      {:ok, Claims.from_map(claims)}
    else
      {:error, reason} -> {:error, reason}
      # cache returned nil / empty keys
      {nil, _} -> {:error, :no_keys}
      {[], _} -> {:error, :no_keys}
    end
  end

  # Read the JOSE header without verifying anything, to learn `kid` and `alg`.
  # A JWT header is unpadded base64url, hence `padding: false`.
  defp decode_header(header_b64) do
    with {:ok, json} <- Base.url_decode64(header_b64, padding: false),
         {:ok, map} when is_map(map) <- Jason.decode(json) do
      map
    else
      _ -> nil
    end
  end

  # Pin RS256. This is the single most important line: without it a token whose
  # header says `alg: none`, or one coercing the RSA key into HMAC, could verify.
  defp check_alg(%{"alg" => "RS256"}), do: :ok
  defp check_alg(_), do: {:error, :invalid}

  defp select_key(keys, kid) do
    key =
      Enum.find(keys, fn k ->
        is_map(k) and k["kty"] == "RSA" and (kid in [nil, ""] or k["kid"] == kid)
      end)

    case key do
      nil -> {:error, :invalid}
      k -> {:ok, k}
    end
  end

  # RS256 signature verification via JOSE. `verify_strict/3` pins the accepted
  # algorithms to our list, so the key material can never be used under a
  # different algorithm than we intend.
  defp verify_signature(key_map, token) do
    jwk = JOSE.JWK.from_map(key_map)

    case JOSE.JWT.verify_strict(jwk, ["RS256"], token) do
      {true, %JOSE.JWT{fields: claims}, _jws} when is_map(claims) -> {:ok, claims}
      _ -> {:error, :invalid}
    end
  rescue
    _ -> {:error, :invalid}
  end

  defp check_issuer(%{"iss" => iss}, issuer) when iss == issuer, do: :ok
  defp check_issuer(_claims, _issuer), do: {:error, :invalid}

  defp check_time(claims, now_sec, leeway) do
    exp = num(claims["exp"])
    nbf = num(claims["nbf"])
    iat = num(claims["iat"])

    cond do
      exp != nil and now_sec > exp + leeway -> {:error, :invalid}
      nbf != nil and now_sec + leeway < nbf -> {:error, :invalid}
      iat != nil and iat - leeway > now_sec -> {:error, :invalid}
      true -> :ok
    end
  end

  # §13.1 token-confusion guard.
  defp check_token_confusion(claims) do
    token_use = claims["token_use"]

    cond do
      token_use != nil and token_use != "session" -> {:error, :invalid}
      Map.has_key?(claims, "aud") -> {:error, :invalid}
      true -> :ok
    end
  end

  defp check_azp(_claims, []), do: :ok

  defp check_azp(claims, parties) do
    case claims["azp"] do
      azp when is_binary(azp) ->
        if azp in parties, do: :ok, else: {:error, :unauthorized_party}

      _ ->
        {:error, :unauthorized_party}
    end
  end

  defp num(n) when is_integer(n), do: n
  defp num(n) when is_float(n), do: trunc(n)
  defp num(_), do: nil

  # --- config resolution ---------------------------------------------------

  defp required(opts, key, env_var) do
    value = opts[key] || Application.get_env(:atlas_auth, key) || System.get_env(env_var)

    if value in [nil, ""] do
      raise ArgumentError,
            "AtlasAuth.Verifier requires #{inspect(key)}: pass it as an option, " <>
              "set config :atlas_auth, #{inspect(key)}: ..., or #{env_var} in the environment."
    end

    value
  end

  # --- header helpers ------------------------------------------------------

  defp header(headers, name) when is_list(headers) do
    Enum.find_value(headers, fn
      {k, v} -> if String.downcase(to_string(k)) == name, do: to_string(v), else: nil
      _ -> nil
    end)
  end

  defp header(headers, name) when is_map(headers) do
    Enum.find_value(headers, fn {k, v} ->
      if String.downcase(to_string(k)) == name, do: to_string(v), else: nil
    end)
  end

  defp header(_headers, _name), do: nil

  defp cookie(nil, _name), do: nil

  defp cookie(cookie_header, name) do
    cookie_header
    |> String.split(";")
    |> Enum.find_value(fn part ->
      case String.split(String.trim(part), "=", parts: 2) do
        [^name, value] -> value
        _ -> nil
      end
    end)
  end

  # --- default (zero-dependency) HTTP fetcher ------------------------------

  @doc false
  def default_fetch(url) do
    _ = :inets.start()
    _ = :ssl.start()

    request = {String.to_charlist(url), [{~c"accept", ~c"application/json"}]}
    http_opts = [{:timeout, 10_000}, {:connect_timeout, 5_000}]
    opts = [{:body_format, :binary}]

    case :httpc.request(:get, request, http_opts, opts) do
      {:ok, {{_v, status, _r}, _h, body}} when status >= 200 and status < 300 ->
        case Jason.decode(body) do
          {:ok, %{"keys" => keys}} when is_list(keys) -> {:ok, keys}
          _ -> {:error, :malformed_jwks}
        end

      {:ok, {{_v, status, _r}, _h, _body}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
