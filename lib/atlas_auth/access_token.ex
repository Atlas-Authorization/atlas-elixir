defmodule AtlasAuth.AccessToken do
  @moduledoc """
  Access-token verification for your own API (an OAuth 2.0 resource server).

  Atlas, acting as your authorization server, issues access tokens for the APIs
  you register as resource servers. `verify/2` checks one locally against the
  instance JWKS — RS256 or ES256, nothing else: the issuer, expiry, that it IS
  an access token, that its `aud` names your API (RFC 8707), and the scopes a
  route needs. A refusal carries the RFC 6750 / RFC 9728 `WWW-Authenticate`
  challenge to answer with.

  Options are those of `AtlasAuth.Verifier.verify/2` (`:jwks_url`, `:issuer`,
  `:fetcher`, `:now_ms`, ...) plus:

    * `:audience` — your API identifier(s) (string or list). Required unless
      `any_audience: true`.
    * `:required_scopes` — scopes every request must carry.
    * `:resource_metadata_url` — advertised as `resource_metadata`.
    * `:realm` — the `WWW-Authenticate` realm.
    * `:method`, `:url`, `:dpop` — the request method, URL (absolute, or a
      path resolved against `:public_origin`) and `DPoP` header, which a DPoP
      proof is checked against. The plug fills them in.
    * `:require_dpop` — refuse every token that is not DPoP-bound and
      challenge with the `DPoP` scheme.
    * `:public_origin` — this API's public origin (`https://api.example.com`)
      for the DPoP `htu` when the URL is a path. Set it behind a proxy.
    * `:dpop_replay_store` — a module implementing `AtlasAuth.DPoP.ReplayStore`
      (or a 2-arity function); default `AtlasAuth.DPoP.MemoryReplayStore`.
    * `:dpop_nonces` — e.g. `AtlasAuth.DPoP.HmacNonce.new(secret)`: every
      proof must carry a nonce it issued (`use_dpop_nonce` otherwise), and
      every result carries `dpop_nonce` for the `DPoP-Nonce` header.
    * `:introspection` — validate opaque access tokens (and, with
      `introspect_jwts: true`, JWTs too) at Atlas's RFC 7662 introspection
      endpoint with your API's client credentials, cached briefly:
      `[client_id: ..., client_secret: ...]` (see `AtlasAuth.Introspection`).

  Sender-constrained tokens (RFC 9449 DPoP) are enforced: a token bound to a key
  (`cnf.jkt`) is accepted only with the `DPoP` scheme and a valid DPoP proof
  from that key, never as a plain Bearer token.
  """

  alias AtlasAuth.{DPoP, Verifier}

  @clock_skew_seconds 5

  @type refusal :: %{
          status: 400 | 401 | 403,
          error: String.t() | nil,
          description: String.t(),
          www_authenticate: String.t(),
          dpop_nonce: String.t() | nil
        }

  @doc """
  Verify an `Authorization` header value (`Bearer` or `DPoP` scheme). Returns
  `{:ok, %{claims:, scopes:, subject:, client_id:, dpop_bound:, dpop_nonce:}}` or
  `{:error, refusal}`.
  """
  @spec verify(String.t() | nil, keyword()) :: {:ok, map()} | {:error, refusal()}
  def verify(authorization, opts \\ []) do
    required = Keyword.get(opts, :required_scopes, [])
    opts = Keyword.put(opts, :__dpop_nonce, DPoP.nonce_current(opts[:dpop_nonces]))
    value = String.trim(authorization || "")

    cond do
      value == "" ->
        refuse(401, nil, "Authentication required.", required, opts)

      true ->
        case Regex.run(~r/^(Bearer|DPoP)\s+([A-Za-z0-9\-._~+\/]+=*)$/i, value) do
          nil ->
            refuse(400, "invalid_request", "Malformed Authorization header.", required, opts)

          [_, scheme, token] ->
            check(token, String.downcase(scheme) == "dpop", required, opts)
        end
    end
  end

  defp check(token, presented_dpop, required, opts) do
    parts = String.split(token, ".")
    introspection = opts[:introspection]

    if length(parts) != 3 or (introspection != nil and introspection[:introspect_jwts] == true) do
      check_introspected(token, presented_dpop, required, opts, introspection)
    else
      check_jwt(token, parts, presented_dpop, required, opts)
    end
  end

  # An opaque token (or a JWT the caller wants checked live) is validated by Atlas itself.
  defp check_introspected(_token, _presented_dpop, required, opts, nil) do
    refuse(401, "invalid_token", "The access token is not a JWT; configure `introspection` to accept opaque tokens.", required, opts)
  end

  defp check_introspected(token, presented_dpop, required, opts, introspection) do
    invalid = "The access token is invalid or expired."
    issuer = opts |> Verifier.required(:issuer, "ATLAS_ISSUER") |> String.trim_trailing("/")
    now_ms = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    now = div(now_ms, 1000)

    case AtlasAuth.Introspection.introspect(token, issuer, Keyword.put_new(introspection, :now_ms, now_ms)) do
      {:error, _} ->
        refuse(401, "invalid_token", "The access token could not be validated right now.", required, opts)

      {:ok, nil} ->
        refuse(401, "invalid_token", invalid, required, opts)

      {:ok, claims} ->
        exp = claims["exp"]
        token_use = claims["token_use"]
        iss_ok? = not Map.has_key?(claims, "iss") or String.trim_trailing(to_string(claims["iss"]), "/") == issuer

        cond do
          not iss_ok? -> refuse(401, "invalid_token", "The access token was issued by another authorization server.", required, opts)
          is_number(exp) and exp + @clock_skew_seconds <= now -> refuse(401, "invalid_token", invalid, required, opts)
          token_use != nil and token_use != "access_token" -> refuse(401, "invalid_token", "The token is not an access token.", required, opts)
          not audience_ok?(claims["aud"], opts) -> refuse(401, "invalid_token", "The access token was not issued for this resource.", required, opts)
          true -> check_binding(token, claims, presented_dpop, required, opts)
        end
    end
  end

  defp check_jwt(token, parts, presented_dpop, required, opts) do
    invalid = "The access token is invalid or expired."
    issuer = opts |> Verifier.required(:issuer, "ATLAS_ISSUER") |> String.trim_trailing("/")
    now = div(Keyword.get(opts, :now_ms, System.system_time(:millisecond)), 1000)

    with true <- length(parts) == 3 || :malformed,
         {:ok, _header, claims} <- Verifier.verify_signed(token, parts, opts) do
      exp = claims["exp"]
      nbf = claims["nbf"]
      token_use = claims["token_use"]

      cond do
        claims["iss"] != issuer -> refuse(401, "invalid_token", invalid, required, opts)
        not is_number(exp) or now > exp + @clock_skew_seconds -> refuse(401, "invalid_token", invalid, required, opts)
        is_number(nbf) and now + @clock_skew_seconds < nbf -> refuse(401, "invalid_token", invalid, required, opts)
        token_use != nil and token_use != "access_token" -> refuse(401, "invalid_token", "The token is not an access token.", required, opts)
        not audience_ok?(claims["aud"], opts) -> refuse(401, "invalid_token", "The access token was not issued for this resource.", required, opts)
        true -> check_binding(token, claims, presented_dpop, required, opts)
      end
    else
      :malformed -> refuse(401, "invalid_token", "The access token is malformed.", required, opts)
      {:error, :no_keys} -> refuse(401, "invalid_token", "No signing keys are available to verify the token.", required, opts)
      _ -> refuse(401, "invalid_token", invalid, required, opts)
    end
  end

  defp audience_ok?(aud, opts) do
    if Keyword.get(opts, :any_audience, false) do
      true
    else
      wanted = opts |> Keyword.get(:audience, []) |> List.wrap()
      got = aud |> List.wrap() |> Enum.filter(&is_binary/1)
      wanted != [] and Enum.any?(got, &(&1 in wanted))
    end
  end

  # Sender constraint (RFC 9449). A bound token is only ever a DPoP token.
  defp check_binding(token, claims, presented_dpop, required, opts) do
    cnf = claims["cnf"]
    bound? = is_map(cnf) and Map.has_key?(cnf, "jkt")
    jkt = if bound?, do: cnf["jkt"]
    dpop = opts[:dpop] && String.trim(opts[:dpop])

    cond do
      bound? and not (is_binary(jkt) and jkt != "") ->
        refuse(401, "invalid_token", "The access token is invalid or expired.", required, opts)

      not (bound? or opts[:require_dpop] == true or presented_dpop) ->
        check_scopes(claims, nil, required, opts)

      not bound? ->
        refuse(401, "invalid_token", "This resource requires a DPoP-bound access token.", required, opts, "DPoP")

      not presented_dpop ->
        refuse(401, "invalid_token", "A DPoP-bound access token must be sent with the DPoP scheme.", required, opts, "DPoP")

      dpop in [nil, ""] ->
        refuse(401, "invalid_dpop_proof", "A DPoP proof is required.", required, opts, "DPoP")

      true ->
        ctx = %{
          token: token,
          jkt: jkt,
          method: (opts[:method] || "GET") |> to_string() |> String.upcase(),
          url: to_string(opts[:url] || ""),
          public_origin: opts[:public_origin],
          now_ms: Keyword.get(opts, :now_ms, System.system_time(:millisecond)),
          replay: Keyword.get(opts, :dpop_replay_store, AtlasAuth.DPoP.MemoryReplayStore),
          nonces: opts[:dpop_nonces]
        }

        case DPoP.check_proof(dpop, ctx) do
          :ok -> check_scopes(claims, jkt, required, opts)
          {:error, error, description} -> refuse(401, error, description, required, opts, "DPoP")
        end
    end
  end

  defp check_scopes(claims, jkt, required, opts) do
    scopes = if is_binary(claims["scope"]), do: String.split(claims["scope"]), else: []
    perms = claims["permissions"] |> List.wrap() |> Enum.filter(&is_binary/1)
    granted = scopes ++ perms

    case Enum.reject(required, &(&1 in granted)) do
      [] ->
        {:ok,
         %{
           claims: claims,
           scopes: scopes,
           subject: claims["sub"] || "",
           client_id: claims["client_id"] || claims["azp"],
           dpop_bound: jkt != nil,
           dpop_nonce: opts[:__dpop_nonce]
         }}

      missing ->
        refuse(403, "insufficient_scope",
          "The access token is missing the required scope(s): #{Enum.join(missing, " ")}.", required, opts)
    end
  end

  defp refuse(status, error, description, required, opts, scheme \\ nil) do
    scope = if error in [nil, "insufficient_scope"], do: required, else: nil
    scheme = scheme || if(opts[:require_dpop] == true, do: "DPoP", else: "Bearer")

    {:error,
     %{
       status: status,
       error: error,
       description: description,
       dpop_nonce: opts[:__dpop_nonce],
       www_authenticate:
         build_www_authenticate(
           scheme: scheme,
           realm: opts[:realm],
           error: error,
           description: description,
           scope: scope,
           resource_metadata_url: opts[:resource_metadata_url]
         )
     }}
  end

  @doc """
  An RFC 6750 / RFC 9449 / RFC 9728 challenge (`:scheme` `"Bearer"`, the
  default, or `"DPoP"`, which also lists the accepted proof algorithms). Without
  `:error` it is the bare "authentication required" challenge (no token was sent).
  """
  @spec build_www_authenticate(keyword()) :: String.t()
  def build_www_authenticate(opts \\ []) do
    q = fn v -> "\"" <> (v |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")) <> "\"" end

    parts =
      [
        opts[:realm] && "realm=" <> q.(opts[:realm]),
        opts[:error] && "error=" <> q.(opts[:error]),
        opts[:error] && opts[:description] && "error_description=" <> q.(opts[:description]),
        opts[:scope] not in [nil, []] && "scope=" <> q.(Enum.join(opts[:scope], " ")),
        opts[:resource_metadata_url] && "resource_metadata=" <> q.(opts[:resource_metadata_url])
      ]
      |> Enum.filter(&is_binary/1)

    scheme = if opts[:scheme] == "DPoP", do: "DPoP", else: "Bearer"
    parts = if scheme == "DPoP", do: parts ++ ["algs=" <> q.(Enum.join(DPoP.algs(), " "))], else: parts
    if parts == [], do: scheme, else: scheme <> " " <> Enum.join(parts, ", ")
  end

  @doc """
  The RFC 9728 protected-resource metadata document for your API. Options:
  `dpop_bound_access_tokens_required: true` advertises that tokens must be
  DPoP-bound (pair it with `:require_dpop`).
  """
  @spec protected_resource_metadata(String.t(), String.t(), [String.t()], keyword()) :: map()
  def protected_resource_metadata(resource, issuer, scopes_supported \\ [], opts \\ []) do
    doc = %{
      "resource" => resource,
      "authorization_servers" => [String.trim_trailing(issuer, "/")],
      "bearer_methods_supported" => ["header"],
      "dpop_signing_alg_values_supported" => DPoP.algs()
    }

    doc = if scopes_supported == [], do: doc, else: Map.put(doc, "scopes_supported", scopes_supported)
    if opts[:dpop_bound_access_tokens_required], do: Map.put(doc, "dpop_bound_access_tokens_required", true), else: doc
  end

  @doc "The RFC 9728 well-known path for a resource identifier."
  @spec protected_resource_metadata_path(String.t()) :: String.t()
  def protected_resource_metadata_path(resource) do
    path = (URI.parse(resource).path || "") |> String.trim_trailing("/")
    "/.well-known/oauth-protected-resource" <> path
  end
end

if Code.ensure_loaded?(Plug.Conn) do
  defmodule AtlasAuth.Plug.RequireAccessToken do
    @moduledoc """
    A Plug that protects an API with an Atlas-issued OAuth access token (Bearer,
    or DPoP with its proof checked against this request). A refusal halts with
    the verifier's status and `WWW-Authenticate` challenge; on success
    `conn.assigns.atlas_access_token` holds the verified token. With
    `:dpop_nonces`, every response carries the `dpop-nonce` header.

        plug AtlasAuth.Plug.RequireAccessToken,
          jwks_url: "...", issuer: "...", audience: "https://api.example.com",
          required_scopes: ["docs:read"]

    Options are those of `AtlasAuth.AccessToken.verify/2`.
    """
    @behaviour Plug

    import Plug.Conn

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts) do
      authorization = conn |> get_req_header("authorization") |> List.first()

      dpop =
        case get_req_header(conn, "dpop") do
          [proof] -> proof
          _ -> nil
        end

      path = conn.request_path <> if(conn.query_string in [nil, ""], do: "", else: "?" <> conn.query_string)
      url = if opts[:public_origin], do: path, else: request_url(conn)
      request_opts = Keyword.merge(opts, method: conn.method, url: url, dpop: dpop)

      case AtlasAuth.AccessToken.verify(authorization, request_opts) do
        {:ok, token} ->
          conn |> put_nonce(token.dpop_nonce) |> assign(:atlas_access_token, token)

        {:error, refusal} ->
          conn
          |> put_nonce(refusal.dpop_nonce)
          |> put_resp_header("www-authenticate", refusal.www_authenticate)
          |> put_resp_content_type("application/json")
          |> send_resp(refusal.status, Jason.encode!(%{error: refusal.error || "unauthorized"}))
          |> halt()
      end
    end

    defp put_nonce(conn, nil), do: conn
    defp put_nonce(conn, nonce), do: put_resp_header(conn, "dpop-nonce", nonce)
  end
end
