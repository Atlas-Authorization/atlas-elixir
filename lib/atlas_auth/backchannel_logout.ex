defmodule AtlasAuth.BackchannelLogout do
  @moduledoc """
  Verify an OpenID Connect Back-Channel Logout `logout_token` (OpenID Connect
  Back-Channel Logout 1.0, §2.6).

  When a user signs out of Atlas (or an administrator ends their session), Atlas
  POSTs a form-encoded `logout_token` to your app's registered back-channel
  logout URI. The token is a JWT signed with the same instance key as every other
  Atlas token, so it is verified against the same cached JWKS as
  `AtlasAuth.Verifier` — no call back to Atlas.

  The checks, in order:

    * shape — a non-empty, three-part JWT, else `:malformed`;
    * algorithm — the header `alg` must be `"RS256"`;
    * header `typ` — when present, must be `"logout+jwt"` (case-insensitive), so
      an ordinary ID token or session token can never be replayed as a logout;
    * signature — RS256 against the JWKS key whose `kid` matches the header;
    * `iss` — must equal the configured issuer;
    * `aud` — must be (or contain) your `:client_id`;
    * `iat` — must be present and not in the future beyond the clock-skew leeway;
    * `exp` — when present, must not have passed (plus leeway);
    * `jti` — must be present (use it to reject replays, see below);
    * `events` — must contain the member
      `"http://schemas.openid.net/event/backchannel-logout"` whose value is a JSON
      object;
    * `sid` and/or `sub` — at least one must be present;
    * `nonce` — must be absent.

  Failure reasons are deliberately coarse, like the session verifier's:
  `:malformed`, `:invalid`, and `:no_keys`.

  ## Options

  Everything `AtlasAuth.Verifier.verify/2` takes (`:jwks_url`, `:issuer`,
  `:leeway`, `:fetcher`, `:cache`, `:now_ms`), plus:

    * `:client_id` — required. Your app's OAuth client id (the token's `aud`).
      Falls back to `Application.get_env(:atlas_auth, :client_id)` then
      `ATLAS_CLIENT_ID`.

  ## Replay protection

  A logout token is single-use. Remember each verified `jti` until the token's
  expiry (or a few minutes when it has none) in a store shared by all your
  instances — your session store, Redis, ETS on a single node — and ignore a
  token whose `jti` you have already seen.
  """

  alias AtlasAuth.Verifier

  @backchannel_event "http://schemas.openid.net/event/backchannel-logout"
  @clock_skew_seconds 5

  @typedoc "The verified logout claims. `sub` or `sid` (or both) is set."
  @type claims :: %{
          sub: String.t() | nil,
          sid: String.t() | nil,
          jti: String.t(),
          iat: integer()
        }

  @type result :: {:ok, claims()} | {:error, Verifier.reason()}

  @doc "The `events` member that marks a back-channel logout token."
  def event, do: @backchannel_event

  @doc """
  Verify a back-channel `logout_token`. Returns
  `{:ok, %{sub: ..., sid: ..., jti: ..., iat: ...}}` or `{:error, reason}`.
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

  def verify(_token, _opts), do: {:error, :malformed}

  defp do_verify(token, parts, opts) do
    issuer = Verifier.required(opts, :issuer, "ATLAS_ISSUER")
    client_id = Verifier.required(opts, :client_id, "ATLAS_CLIENT_ID")
    leeway = Keyword.get(opts, :leeway, @clock_skew_seconds)
    now_ms = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    now_sec = div(now_ms, 1000)

    with {:ok, header, claims} <- Verifier.verify_signed(token, parts, opts),
         :ok <- check_typ(header),
         :ok <- check(claims["iss"] == issuer),
         :ok <- check_aud(claims["aud"], client_id),
         :ok <- check_time(claims, now_sec, leeway),
         :ok <- check(is_binary(claims["jti"]) and claims["jti"] != ""),
         :ok <- check_events(claims["events"]),
         :ok <- check_subject(claims),
         :ok <- check(not Map.has_key?(claims, "nonce")) do
      {:ok,
       %{
         sub: str(claims["sub"]),
         sid: str(claims["sid"]),
         jti: claims["jti"],
         iat: num(claims["iat"])
       }}
    end
  end

  defp check(true), do: :ok
  defp check(_), do: {:error, :invalid}

  defp check_typ(header) do
    case header["typ"] do
      nil -> :ok
      typ when is_binary(typ) -> check(String.downcase(typ) == "logout+jwt")
      _ -> {:error, :invalid}
    end
  end

  defp check_aud(aud, client_id) when is_binary(aud), do: check(aud == client_id)
  defp check_aud(aud, client_id) when is_list(aud), do: check(client_id in aud)
  defp check_aud(_aud, _client_id), do: {:error, :invalid}

  defp check_time(claims, now_sec, leeway) do
    iat = num(claims["iat"])
    exp = num(claims["exp"])

    cond do
      iat == nil -> {:error, :invalid}
      iat - leeway > now_sec -> {:error, :invalid}
      Map.has_key?(claims, "exp") and exp == nil -> {:error, :invalid}
      exp != nil and now_sec > exp + leeway -> {:error, :invalid}
      true -> :ok
    end
  end

  defp check_events(%{@backchannel_event => value}) when is_map(value), do: :ok
  defp check_events(_), do: {:error, :invalid}

  defp check_subject(claims) do
    check(str(claims["sub"]) != nil or str(claims["sid"]) != nil)
  end

  defp str(s) when is_binary(s) and s != "", do: s
  defp str(_), do: nil

  defp num(n) when is_integer(n), do: n
  defp num(n) when is_float(n), do: trunc(n)
  defp num(_), do: nil
end
