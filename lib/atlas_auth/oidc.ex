defmodule AtlasAuth.OIDC do
  @moduledoc """
  The hosted-redirect OpenID Connect relying party: authorization-code flow with
  PKCE (S256), `state` and `nonce`, ID-token verification against the issuer's
  JWKS, and RP-initiated logout.

      {:ok, %{url: url, cookie: cookie}} =
        AtlasAuth.OIDC.start(issuer: issuer, client_id: id, redirect_uri: cb, secret: secret)
      # 302 to `url`, with `cookie` as a Set-Cookie header ...

      {:ok, identity} =
        AtlasAuth.OIDC.callback(
          issuer: issuer, client_id: id, client_secret: client_secret, redirect_uri: cb, secret: secret,
          query: conn.query_params, cookie: cookie_header
        )

  The flow cookie (state, nonce and the PKCE verifier) is sealed with AES-256-GCM
  under a key derived from `:secret` (at least 32 characters), short-lived
  (10 minutes), `HttpOnly`, `SameSite=Lax`, and scoped to the callback path. The
  ID token is checked for algorithm (RS256, ES256, ES384, PS256 or EdDSA, pinned before any key lookup),
  signature, `iss`, `aud` / `azp`, `exp` / `iat`, `nonce` and `at_hash`.

  Most apps use `AtlasAuth.RP` (sessions, keep-alive, sign-out) and
  `AtlasAuth.Plug.RP` (the routes) instead of calling this module directly.

  ## Options common to every function

    * `:issuer` (required) - your instance's issuer, `https://` plus its frontend API host.
    * `:client_id` (required) - the OAuth client id.
    * `:http` - an HTTP function `(method, url, headers, body -> {:ok, %{status:, headers:, body:}} | {:error, term})`
      (default: `:httpc`, TLS verified).
    * `:now_ms` - the clock in epoch milliseconds (tests).
    * `:discovery_url` - override `<issuer>/.well-known/openid-configuration`.
  """

  alias AtlasAuth.{Http, Verifier}
  alias AtlasAuth.OIDC.Error

  @flow_cookie "atlas_oidc"
  @flow_max_age 600
  @discovery_ttl_ms 3_600_000
  @discovery_retry_ms 60_000
  @owned_params ~w(response_type client_id redirect_uri state nonce code_challenge code_challenge_method)
  @sealed "s1."
  @plain "p1."

  @doc "The default flow cookie name."
  def flow_cookie_name, do: @flow_cookie

  @doc "How long a started sign-in stays valid, in seconds."
  def flow_max_age_seconds, do: @flow_max_age

  # -- start ------------------------------------------------------------------

  @doc """
  Begin a sign-in: build the authorize URL and the flow cookie.

  Returns `{:ok, %{url:, cookie:, state:, nonce:}}`. Send `cookie` as `Set-Cookie`
  and redirect the browser to `url`.

  Options: `:redirect_uri` (required, registered on the client exactly; https, or
  http on localhost), `:secret` (seals the cookie; strongly recommended), `:scope`
  (default `openid profile email`), `:prompt`, `:login_hint`, `:audience_hint`,
  `:organization`, `:ui_locales`, `:max_age` (seconds; the callback then requires an
  `auth_time` inside the window), `:return_to` (a same-site path, never an open
  redirect), `:expected_sub` (a step-up for an already signed-in user),
  `:extra_params` (more authorize parameters; the ones this module owns are ignored),
  `:cookie_name`.
  """
  @spec start(keyword()) :: {:ok, map()} | {:error, Error.t()}
  def start(opts) do
    with :ok <- require_string(opts, :issuer),
         :ok <- require_string(opts, :client_id),
         {:ok, redirect} <- parse_redirect_uri(opts[:redirect_uri]),
         :ok <- check_max_age(opts[:max_age]),
         :ok <- check_return_to(opts[:return_to]),
         {:ok, discovery} <- discover(opts) do
      state = random_token()
      nonce = random_token()
      verifier = random_token()
      challenge = Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)

      extra =
        for {k, v} <- Map.new(opts[:extra_params] || %{}, fn {k, v} -> {to_string(k), v} end),
            v != nil,
            k not in @owned_params,
            do: {k, to_string(v)}

      params =
        extra ++
          [
            {"response_type", "code"},
            {"client_id", opts[:client_id]},
            {"redirect_uri", opts[:redirect_uri]},
            {"scope", normalise_scope(opts[:scope])},
            {"state", state},
            {"nonce", nonce},
            {"code_challenge", challenge},
            {"code_challenge_method", "S256"}
          ] ++
          optional([
            {"prompt", opts[:prompt]},
            {"login_hint", opts[:login_hint]},
            {"audience_hint", opts[:audience_hint]},
            {"organization", opts[:organization]},
            {"ui_locales", opts[:ui_locales]},
            {"max_age", opts[:max_age] && to_string(opts[:max_age])}
          ])

      payload =
        %{
          "s" => state,
          "n" => nonce,
          "v" => verifier,
          "r" => opts[:redirect_uri],
          "i" => strip_slash(opts[:issuer]),
          "c" => opts[:client_id],
          "t" => div(now_ms(opts), 1000)
        }
        |> put_if("m", opts[:max_age])
        |> put_if("u", opts[:return_to])
        |> put_if("x", opts[:expected_sub])

      with {:ok, value} <- seal(payload, opts[:secret]) do
        cookie =
          serialize_cookie(opts[:cookie_name] || @flow_cookie, value,
            path: redirect.path || "/",
            max_age: @flow_max_age,
            secure: redirect.scheme == "https"
          )

        {:ok, %{url: append_query(discovery.authorization_endpoint, params), cookie: cookie, state: state, nonce: nonce}}
      end
    end
  end

  # -- callback ---------------------------------------------------------------

  @doc """
  Finish a sign-in: check `state`, exchange the code (PKCE and client authentication),
  verify the ID token and return who signed in.

  Options: `:redirect_uri`, `:secret` (the same as `start/1`), `:query` (the callback's
  query params: a map with string keys, or a query string), `:cookie` (the request's
  `Cookie` header, or the bare flow-cookie value), `:client_secret`, `:client_auth`
  (`:client_secret_basic` (default with a secret), `:client_secret_post` or `:none`),
  `:clock_tolerance_sec` (default 60), `:cookie_name`.

  Returns `{:ok, identity}`: `sub`, `namespaced_sub`, `email`, `email_verified`, `name`,
  `sid`, `auth_time`, `return_to`, `organization`, `organizations`, `sso`, `id_token`,
  `access_token`, `refresh_token`, `expires_at` (epoch ms), `claims` and `clear_cookie`
  (a `Set-Cookie` value that removes the flow cookie: send it with your response).
  On failure `{:error, %AtlasAuth.OIDC.Error{}}`, whose `clear_cookie` is set too.
  """
  @spec callback(keyword()) :: {:ok, map()} | {:error, Error.t()}
  def callback(opts) do
    name = opts[:cookie_name] || @flow_cookie

    clear =
      case parse_redirect_uri(opts[:redirect_uri]) do
        {:ok, r} -> serialize_cookie(name, "", path: r.path || "/", max_age: 0, secure: r.scheme == "https")
        _ -> nil
      end

    case run_callback(opts, name) do
      {:ok, identity} -> {:ok, Map.put(identity, :clear_cookie, clear)}
      {:error, %Error{} = e} -> {:error, %{e | clear_cookie: clear}}
    end
  end

  defp run_callback(opts, name) do
    with :ok <- require_string(opts, :issuer),
         :ok <- require_string(opts, :client_id),
         issuer = strip_slash(opts[:issuer]),
         query = to_params(opts[:query]),
         {:ok, flow} <- open_flow_cookie(opts[:cookie], name, opts[:secret]),
         :ok <- check_state(query, flow),
         now_sec = div(now_ms(opts), 1000),
         :ok <- check_age(flow, now_sec),
         :ok <- check_flow_binding(flow, issuer, opts),
         :ok <- check_returned_issuer(query, issuer),
         :ok <- check_oauth_error(query),
         {:ok, code} <- fetch_code(query),
         {:ok, discovery} <- discover(opts),
         {:ok, tokens} <- exchange_code(discovery, opts, code, flow["v"]),
         {:ok, claims} <-
           verify_id_token(tokens["id_token"],
             issuer: discovery.issuer,
             jwks_url: discovery.jwks_uri,
             client_id: opts[:client_id],
             nonce: flow["n"],
             access_token: tokens["access_token"],
             clock_tolerance_sec: opts[:clock_tolerance_sec] || 60,
             http: opts[:http],
             now_ms: opts[:now_ms],
             fetcher: opts[:fetcher]
           ),
         auth_time = if(is_number(claims["auth_time"]), do: claims["auth_time"], else: nil),
         :ok <- check_max_age_window(flow, auth_time, now_sec, opts),
         :ok <- check_expected_sub(flow, claims["sub"]) do
      sub = claims["sub"]
      expires_in = number(tokens["expires_in"])

      expires_at =
        if expires_in && expires_in > 0, do: now_ms(opts) + trunc(expires_in * 1000), else: trunc(claims["exp"] * 1000)

      {:ok,
       %{
         sub: sub,
         namespaced_sub: issuer <> "#" <> sub,
         email: str(claims["email"]),
         email_verified: claims["email_verified"] == true,
         name: str(claims["name"]),
         sid: if(is_binary(claims["sid"]) and claims["sid"] != "", do: claims["sid"]),
         auth_time: auth_time,
         return_to: if(is_binary(flow["u"]) and safe_return_to?(flow["u"]), do: flow["u"]),
         organization: organization_of(claims),
         organizations: organizations_of(claims),
         sso: sso_of(claims),
         id_token: tokens["id_token"],
         access_token: tokens["access_token"],
         refresh_token: if(is_binary(tokens["refresh_token"]), do: tokens["refresh_token"]),
         expires_at: expires_at,
         claims: claims
       }}
    end
  end

  defp check_state(query, flow) do
    state = query["state"]

    if is_binary(state) and secure_equal?(state, flow["s"]),
      do: :ok,
      else: {:error, err(:state_mismatch, "The `state` returned to the callback does not match this browser's sign-in.")}
  end

  defp check_age(flow, now_sec) do
    if now_sec - flow["t"] > @flow_max_age,
      do: {:error, err(:state_mismatch, "This sign-in took longer than 10 minutes. Start sign-in again.")},
      else: :ok
  end

  defp check_flow_binding(flow, issuer, opts) do
    if flow["i"] == issuer and flow["c"] == opts[:client_id] and flow["r"] == opts[:redirect_uri],
      do: :ok,
      else: {:error, err(:state_mismatch, "This sign-in was started for a different issuer, client or redirect URI.")}
  end

  # RFC 9207: an authorization server that names itself must be the one we sent the user to.
  defp check_returned_issuer(query, issuer) do
    case query["iss"] do
      nil -> :ok
      iss -> if strip_slash(iss) == issuer, do: :ok, else: {:error, err(:issuer_mismatch, "The callback came from #{iss}, not #{issuer}.")}
    end
  end

  defp check_oauth_error(query) do
    case query["error"] do
      e when is_binary(e) and e != "" ->
        d = query["error_description"]
        suffix = if d, do: " (#{d})", else: ""
        {:error, err(:access_denied, "Sign-in did not complete: #{e}#{suffix}.", oauth_error: e, description: d)}

      _ ->
        :ok
    end
  end

  defp fetch_code(query) do
    case query["code"] do
      c when is_binary(c) and c != "" -> {:ok, c}
      _ -> {:error, err(:invalid_request, "The callback has no `code` parameter.")}
    end
  end

  # OIDC Core 3.1.2.1: with max_age the client must check auth_time itself.
  defp check_max_age_window(%{"m" => m}, auth_time, now_sec, opts) do
    tolerance = opts[:clock_tolerance_sec] || 60

    if auth_time == nil or now_sec - auth_time > m + tolerance,
      do:
        {:error,
         err(:reauthentication_required, "The sign-in is older than the #{m} seconds this request allowed (max_age). Ask the user to sign in again.")},
      else: :ok
  end

  defp check_max_age_window(_flow, _auth_time, _now_sec, _opts), do: :ok

  defp check_expected_sub(%{"x" => x}, sub) do
    if secure_equal?(sub, x), do: :ok, else: {:error, err(:subject_mismatch, "A different user signed in than the one asked to confirm it is them.")}
  end

  defp check_expected_sub(_flow, _sub), do: :ok

  defp exchange_code(discovery, opts, code, verifier) do
    secret = opts[:client_secret]
    method = opts[:client_auth] || if(secret, do: :client_secret_basic, else: :none)

    if method != :none and secret in [nil, ""] do
      {:error, err(:token_exchange_failed, "client_auth #{method} needs `client_secret`.")}
    else
      form = [
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", opts[:redirect_uri]},
        {"code_verifier", verifier}
      ]

      base = [{"content-type", "application/x-www-form-urlencoded"}, {"accept", "application/json"}]

      {headers, form} =
        case method do
          :client_secret_basic -> {[{"authorization", basic(opts[:client_id], secret)} | base], form}
          :client_secret_post -> {base, form ++ [{"client_id", opts[:client_id]}, {"client_secret", secret}]}
          _ -> {base, form ++ [{"client_id", opts[:client_id]}]}
        end

      case Http.request(:post, discovery.token_endpoint, headers, URI.encode_query(form), http_opts(opts)) do
        {:error, reason} ->
          {:error, err(:token_exchange_failed, "The token endpoint could not be reached: #{inspect(reason)}.")}

        {:ok, %{status: status} = res} when status in 200..299 ->
          case Http.json(res) do
            %{"id_token" => id, "access_token" => at} = json when is_binary(id) and is_binary(at) ->
              {:ok, json}

            _ ->
              {:error, err(:token_exchange_failed, "The token response has no `id_token`. Request the `openid` scope.", status: status)}
          end

        {:ok, %{status: status} = res} ->
          json = Http.json(res) || %{}
          e = if is_binary(json["error"]), do: json["error"]
          d = if is_binary(json["error_description"]), do: json["error_description"]
          msg = "The token endpoint answered #{status}#{if e, do: " " <> e, else: ""}#{if d, do: ": " <> d, else: ""}."
          {:error, err(:token_exchange_failed, msg, oauth_error: e, description: d, status: status)}
      end
    end
  end

  # -- ID-token verification ---------------------------------------------------

  @doc """
  Verify an ID token on its own (for an app that does its own code exchange). Same
  checks as `callback/1`. Options: `:issuer`, `:jwks_url` (found by discovery when
  omitted), `:client_id`, `:nonce` (required), `:access_token` (checked against
  `at_hash`), `:clock_tolerance_sec` (default 60), `:fetcher` (the JWKS fetcher of
  `AtlasAuth.Verifier`), `:http`, `:now_ms`.

  Returns `{:ok, claims}` or `{:error, %AtlasAuth.OIDC.Error{code: :invalid_token}}`.
  """
  @spec verify_id_token(String.t(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def verify_id_token(id_token, opts) do
    with {:ok, jwks_url, issuer} <- ensure_discovery(opts) do
      tol = opts[:clock_tolerance_sec] || 60
      now_ms = now_ms(opts)
      parts = String.split(id_token || "", ".")

      vopts =
        [jwks_url: jwks_url, now_ms: now_ms] ++
          if(opts[:fetcher], do: [fetcher: opts[:fetcher]], else: []) ++
          if(opts[:cache], do: [cache: opts[:cache]], else: [])

      case Verifier.verify_signed(id_token || "", parts, vopts) do
        {:ok, _header, claims} -> check_claims(claims, issuer, opts, tol, div(now_ms, 1000))
        {:error, :no_keys} -> {:error, err(:discovery_failed, "The issuer's signing keys could not be fetched from #{jwks_url}.")}
        {:error, reason} -> {:error, invalid("it is not a verifiable JWT (RS256, ES256, ES384, PS256 or EdDSA) (#{reason})")}
      end
    end
  end

  defp ensure_discovery(opts) do
    case {opts[:jwks_url], opts[:issuer]} do
      {url, iss} when is_binary(url) and is_binary(iss) ->
        {:ok, url, iss}

      _ ->
        with {:ok, d} <- discover(opts), do: {:ok, opts[:jwks_url] || d.jwks_uri, d.issuer}
    end
  end

  defp check_claims(claims, issuer, opts, tol, now_sec) do
    aud = List.wrap(claims["aud"])
    azp = claims["azp"]

    cond do
      claims["iss"] != issuer -> {:error, invalid("its issuer is not the configured issuer")}
      not is_binary(claims["sub"]) or claims["sub"] == "" -> {:error, invalid("its sub claim is invalid")}
      not (is_number(claims["exp"]) and is_number(claims["iat"])) -> {:error, invalid("its exp or iat claim is invalid")}
      claims["exp"] + tol <= now_sec -> {:error, invalid("it has expired")}
      is_number(claims["nbf"]) and claims["nbf"] - tol > now_sec -> {:error, invalid("its nbf claim is invalid")}
      opts[:client_id] not in aud -> {:error, invalid("its audience is not this client")}
      length(aud) > 1 and azp == nil -> {:error, invalid("it has several audiences and no azp")}
      azp != nil and azp != opts[:client_id] -> {:error, invalid("its azp is #{inspect(azp)}, not this client")}
      not is_binary(claims["nonce"]) or not secure_equal?(claims["nonce"], opts[:nonce] || "") -> {:error, invalid("its nonce does not match this sign-in")}
      claims["iat"] > now_sec + tol -> {:error, invalid("it was issued in the future")}
      not at_hash_ok?(claims, opts[:access_token]) -> {:error, invalid("its at_hash does not match the access token")}
      true -> {:ok, claims}
    end
  end

  defp at_hash_ok?(%{"at_hash" => h}, at) when is_binary(h) and is_binary(at) and at != "" do
    <<half::binary-size(16), _::binary>> = :crypto.hash(:sha256, at)
    secure_equal?(Base.url_encode64(half, padding: false), h)
  end

  defp at_hash_ok?(_claims, _at), do: true

  # -- logout -------------------------------------------------------------------

  @doc """
  The RP-initiated logout URL (`end_session_endpoint` from discovery). Options:
  `:post_logout_redirect_uri` (registered on the client exactly), `:id_token_hint`, `:state`.
  """
  @spec logout_url(keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def logout_url(opts) do
    with {:ok, d} <- discover(opts) do
      case d.end_session_endpoint do
        nil ->
          {:error, err(:discovery_failed, "The issuer does not advertise an end_session_endpoint.")}

        endpoint ->
          params =
            [{"client_id", opts[:client_id]}] ++
              optional([
                {"id_token_hint", opts[:id_token_hint]},
                {"post_logout_redirect_uri", opts[:post_logout_redirect_uri]},
                {"state", opts[:state]}
              ])

          {:ok, append_query(endpoint, params)}
      end
    end
  end

  @doc "A `Set-Cookie` value that removes the flow cookie for this callback path."
  @spec clear_cookie(keyword()) :: String.t()
  def clear_cookie(opts) do
    {:ok, r} = parse_redirect_uri(opts[:redirect_uri])
    serialize_cookie(opts[:cookie_name] || @flow_cookie, "", path: r.path || "/", max_age: 0, secure: r.scheme == "https")
  end

  # -- claims helpers -----------------------------------------------------------

  @doc "The organization (`org_*` claims) a sign-in was made in, or `nil`."
  def organization_of(%{"org_id" => id} = c) when is_binary(id) do
    %{
      id: id,
      slug: str(c["org_slug"]) || "",
      role: str(c["org_role"]) || "",
      permissions: if(is_list(c["org_permissions"]), do: Enum.filter(c["org_permissions"], &is_binary/1), else: [])
    }
  end

  def organization_of(_), do: nil

  @doc "The `orgs` membership list (the `organizations` scope), or `nil`."
  def organizations_of(%{"orgs" => orgs}) when is_list(orgs) do
    for %{"id" => id} = o <- orgs, is_binary(id), do: %{id: id, slug: str(o["slug"]) || "", role: str(o["role"]) || ""}
  end

  def organizations_of(_), do: nil

  @doc "The enterprise SSO context (`sso_*` claims), or `nil`."
  def sso_of(%{"sso_connection_id" => id} = c) when is_binary(id) do
    %{
      connection_id: id,
      organization_id: str(c["sso_organization_id"]),
      type: if(c["sso_connection_type"] in ["saml", "oidc"], do: c["sso_connection_type"]),
      tenant_id: str(c["sso_tenant_id"]),
      issuer: str(c["sso_issuer"]),
      domain: str(c["sso_domain"])
    }
  end

  def sso_of(_), do: nil

  @doc "A plain same-site path: one leading `/`, no scheme or authority, no backslash or control characters."
  @spec safe_return_to?(term()) :: boolean()
  def safe_return_to?(value) when is_binary(value), do: Regex.match?(~r/\A\/(?![\/\\])[^\\\x00-\x1f\x7f]*\z/, value)
  def safe_return_to?(_), do: false

  @doc "Forget cached discovery documents (tests, or after an issuer change)."
  def reset_caches do
    for {{__MODULE__, :discovery, _} = k, _} <- :persistent_term.get(), do: :persistent_term.erase(k)
    :ok
  end

  # -- discovery -----------------------------------------------------------------

  defp discover(opts) do
    issuer = strip_slash(opts[:issuer] || "")
    url = opts[:discovery_url] || issuer <> "/.well-known/openid-configuration"
    key = {__MODULE__, :discovery, {issuer, url, opts[:http] && :erlang.phash2(opts[:http])}}
    now = now_ms(opts)

    case :persistent_term.get(key, nil) do
      {:ok, doc, at} when now - at < @discovery_ttl_ms ->
        {:ok, doc}

      {:error, error, at} when now - at < @discovery_retry_ms ->
        {:error, error}

      previous ->
        case fetch_discovery(url, issuer, opts) do
          {:ok, doc} ->
            :persistent_term.put(key, {:ok, doc, now})
            {:ok, doc}

          {:error, error} ->
            # Keep serving a document we already had through an outage.
            case previous do
              {:ok, doc, _} ->
                {:ok, doc}

              _ ->
                :persistent_term.put(key, {:error, error, now})
                {:error, error}
            end
        end
    end
  end

  defp fetch_discovery(url, issuer, opts) do
    fail = fn why -> {:error, err(:discovery_failed, "OIDC discovery at #{url} failed: #{why}.")} end

    case Http.request(:get, url, [{"accept", "application/json"}], nil, http_opts(opts)) do
      {:error, reason} ->
        fail.(inspect(reason))

      {:ok, %{status: s}} when s not in 200..299 ->
        fail.("HTTP #{s}")

      {:ok, res} ->
        case Http.json(res) do
          %{"issuer" => doc_issuer} = doc when is_binary(doc_issuer) ->
            cond do
              strip_slash(doc_issuer) != issuer ->
                fail.("its issuer (#{doc_issuer}) is not #{issuer}")

              true ->
                Enum.find_value(~w(authorization_endpoint token_endpoint jwks_uri), fn f ->
                  cond do
                    not is_binary(doc[f]) -> fail.("it has no #{f}")
                    not secure_url?(doc[f]) -> fail.("its #{f} is not an https URL")
                    true -> nil
                  end
                end) ||
                  if(doc["end_session_endpoint"] != nil and not is_binary(doc["end_session_endpoint"]),
                    do: fail.("its end_session_endpoint is not a string"),
                    else:
                      {:ok,
                       %{
                         issuer: doc_issuer,
                         authorization_endpoint: doc["authorization_endpoint"],
                         token_endpoint: doc["token_endpoint"],
                         jwks_uri: doc["jwks_uri"],
                         end_session_endpoint: doc["end_session_endpoint"]
                       }}
                  )
            end

          _ ->
            fail.("the response is not JSON")
        end
    end
  end

  # -- the flow cookie ------------------------------------------------------------

  defp seal(payload, nil), do: {:ok, @plain <> b64(Jason.encode!(payload))}

  defp seal(payload, secret) do
    with {:ok, key} <- flow_key(secret) do
      iv = :crypto.strong_rand_bytes(12)
      {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, Jason.encode!(payload), <<>>, 16, true)
      {:ok, @sealed <> b64(iv) <> "." <> b64(ct <> tag)}
    end
  end

  defp open_flow_cookie(cookie, name, secret) do
    missing = {:error, err(:state_mismatch, "The sign-in flow cookie is missing or expired. Start sign-in again.")}

    case read_flow_cookie(cookie, name) do
      nil ->
        missing

      raw ->
        case open_flow(raw, secret) do
          {:ok, flow} -> {:ok, flow}
          {:raise, e} -> {:error, e}
          :error -> {:error, err(:state_mismatch, "The sign-in flow cookie could not be read. Start sign-in again.")}
        end
    end
  end

  defp open_flow(value, secret) do
    json =
      if secret != nil do
        # With a secret configured an unsealed cookie is a downgrade: refuse it.
        with {:ok, key} <- flow_key(secret),
             @sealed <> rest <- value,
             [iv, data] <- String.split(rest, "."),
             {:ok, iv} <- Base.url_decode64(iv, padding: false),
             {:ok, blob} <- Base.url_decode64(data, padding: false),
             true <- byte_size(blob) > 16,
             ct_size = byte_size(blob) - 16,
             <<ct::binary-size(ct_size), tag::binary-size(16)>> = blob,
             plain when is_binary(plain) <- :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ct, <<>>, tag, false) do
          plain
        else
          {:error, %Error{} = e} -> {:raise, e}
          _ -> :error
        end
      else
        with @plain <> rest <- value, {:ok, plain} <- Base.url_decode64(rest, padding: false), do: plain, else: (_ -> :error)
      end

    with plain when is_binary(plain) <- json,
         {:ok, %{} = p} <- Jason.decode(plain),
         true <- Enum.all?(~w(s n v r i c), &is_binary(p[&1])) and is_integer(p["t"]),
         true <- is_nil(p["m"]) or (is_integer(p["m"]) and p["m"] >= 0),
         true <- is_nil(p["u"]) or is_binary(p["u"]),
         true <- is_nil(p["x"]) or is_binary(p["x"]) do
      {:ok, p}
    else
      {:raise, e} -> {:raise, e}
      _ -> :error
    end
  end

  defp read_flow_cookie(nil, _), do: nil
  defp read_flow_cookie("", _), do: nil

  defp read_flow_cookie(input, name) do
    trimmed = String.trim(input)

    if String.starts_with?(trimmed, [@sealed, @plain]) do
      trimmed
    else
      trimmed
      |> String.split(";")
      |> Enum.find_value(fn part ->
        case String.split(part, "=", parts: 2) do
          [k, v] -> if String.trim(k) == name and String.trim(v) != "", do: String.trim(v)
          _ -> nil
        end
      end)
    end
  end

  # HKDF-SHA256 (RFC 5869), salt "atlas-oidc-flow-cookie", info "v1": the same key the
  # other Atlas relying-party libraries derive, so a flow cookie opens in any of them.
  defp flow_key(secret) when is_binary(secret) and byte_size(secret) >= 32 do
    prk = :crypto.mac(:hmac, :sha256, "atlas-oidc-flow-cookie", secret)
    {:ok, :crypto.mac(:hmac, :sha256, prk, "v1" <> <<1>>)}
  end

  defp flow_key(_), do: {:error, %Error{code: :invalid_request, message: "The OIDC flow-cookie `secret` must be at least 32 characters."}}

  defp serialize_cookie(name, value, o) do
    parts = ["#{name}=#{value}", "Path=#{o[:path]}", "Max-Age=#{o[:max_age]}", "HttpOnly", "SameSite=Lax"]
    parts = if o[:max_age] == 0, do: parts ++ ["Expires=Thu, 01 Jan 1970 00:00:00 GMT"], else: parts
    # Secure except on a plain-http local callback, where the browser would drop it.
    parts = if o[:secure], do: parts ++ ["Secure"], else: parts
    Enum.join(parts, "; ")
  end

  # -- small helpers --------------------------------------------------------------

  defp err(code, message, extra \\ []), do: struct(Error, [code: code, message: message] ++ extra)
  defp invalid(why), do: err(:invalid_token, "The ID token was refused: #{why}.")

  defp require_string(opts, key) do
    case opts[key] do
      v when is_binary(v) and v != "" -> :ok
      _ -> {:error, err(:invalid_request, "oidc: `#{key}` is required.")}
    end
  end

  defp parse_redirect_uri(value) when is_binary(value) and value != "" do
    case URI.parse(value) do
      %URI{scheme: "https", host: h} = u when is_binary(h) -> {:ok, u}
      %URI{scheme: "http", host: h} = u when h in ["localhost", "127.0.0.1", "[::1]", "::1"] -> {:ok, u}
      %URI{scheme: s} when s in ["http", "https"] -> {:error, err(:invalid_request, "oidc: `redirect_uri` must be https (http is accepted only for localhost).")}
      _ -> {:error, err(:invalid_request, "oidc: `redirect_uri` must be an absolute URL.")}
    end
  end

  defp parse_redirect_uri(_), do: {:error, err(:invalid_request, "oidc: `redirect_uri` is required.")}

  defp check_max_age(nil), do: :ok
  defp check_max_age(n) when is_integer(n) and n >= 0, do: :ok
  defp check_max_age(_), do: {:error, err(:invalid_request, "oidc: `max_age` must be a whole number of seconds, 0 or more.")}

  defp check_return_to(nil), do: :ok

  defp check_return_to(v),
    do: if(safe_return_to?(v), do: :ok, else: {:error, err(:invalid_request, "oidc: `return_to` must be a path on this site, starting with a single `/`.")})

  defp normalise_scope(scope) do
    parts = (scope || "openid profile email") |> String.split(~r/\s+/, trim: true)
    parts = if "openid" in parts, do: parts, else: ["openid" | parts]
    parts |> Enum.uniq() |> Enum.join(" ")
  end

  defp to_params(nil), do: %{}
  defp to_params(q) when is_binary(q), do: q |> String.split("?", parts: 2) |> List.last() |> String.split("#") |> hd() |> URI.decode_query()

  defp to_params(q) when is_map(q) or is_list(q) do
    for {k, v} <- q, into: %{} do
      {to_string(k), if(is_list(v), do: List.first(v), else: v)}
    end
  end

  defp optional(pairs), do: for({k, v} <- pairs, v not in [nil, ""], do: {k, v})
  defp put_if(map, _k, nil), do: map
  defp put_if(map, k, v), do: Map.put(map, k, v)

  defp append_query(url, params) do
    uri = URI.parse(url)
    existing = if uri.query, do: [uri.query], else: []
    URI.to_string(%{uri | query: Enum.join(existing ++ [URI.encode_query(params, :rfc3986)], "&")})
  end

  # RFC 6749 2.3.1: both halves are form-encoded before Basic encoding.
  defp basic(id, secret), do: "Basic " <> Base.encode64(URI.encode_www_form(id) <> ":" <> URI.encode_www_form(secret))

  defp http_opts(opts), do: Keyword.take(opts, [:http, :timeout_ms])
  defp now_ms(opts), do: opts[:now_ms] || System.system_time(:millisecond)
  defp strip_slash(v), do: String.replace(v, ~r/\/+\z/, "")
  defp b64(bin), do: Base.url_encode64(bin, padding: false)
  defp random_token, do: b64(:crypto.strong_rand_bytes(32))
  defp str(v) when is_binary(v), do: v
  defp str(_), do: nil
  defp number(v) when is_number(v), do: v

  defp number(v) when is_binary(v) do
    case Float.parse(v) do
      {n, _} -> n
      _ -> nil
    end
  end

  defp number(_), do: nil

  defp secure_equal?(a, b) when is_binary(a) and is_binary(b) do
    # Length-independent XOR fold, so a mismatch position does not leak.
    n = max(byte_size(a), byte_size(b))
    pa = String.pad_trailing(a, n, <<0>>)
    pb = String.pad_trailing(b, n, <<0>>)

    diff =
      Enum.zip(:binary.bin_to_list(pa), :binary.bin_to_list(pb))
      |> Enum.reduce(byte_size(a) - byte_size(b), fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)

    diff == 0
  end

  defp secure_equal?(_, _), do: false

  defp secure_url?(value) do
    case URI.parse(value) do
      %URI{scheme: "https", host: h} when is_binary(h) -> true
      %URI{scheme: "http", host: h} when h in ["localhost", "127.0.0.1", "[::1]", "::1"] -> true
      _ -> false
    end
  end
end
