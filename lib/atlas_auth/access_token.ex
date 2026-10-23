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

  DPoP-bound tokens (`cnf.jkt`) are refused: this checks Bearer tokens only.
  """

  alias AtlasAuth.Verifier

  @clock_skew_seconds 5

  @type refusal :: %{status: 400 | 401 | 403, error: String.t() | nil, description: String.t(), www_authenticate: String.t()}

  @doc """
  Verify an `Authorization` header value. Returns `{:ok, %{claims:, scopes:,
  subject:, client_id:}}` or `{:error, refusal}`.
  """
  @spec verify(String.t() | nil, keyword()) :: {:ok, map()} | {:error, refusal()}
  def verify(authorization, opts \\ []) do
    required = Keyword.get(opts, :required_scopes, [])
    value = String.trim(authorization || "")

    cond do
      value == "" ->
        refuse(401, nil, "Authentication required.", required, opts)

      true ->
        case Regex.run(~r/^(Bearer|DPoP)\s+([A-Za-z0-9\-._~+\/]+=*)$/i, value) do
          nil ->
            refuse(400, "invalid_request", "Malformed Authorization header.", required, opts)

          [_, scheme, token] ->
            if String.downcase(scheme) == "dpop" do
              refuse(401, "invalid_token", "DPoP-bound access tokens are not accepted here.", required, opts)
            else
              check(token, required, opts)
            end
        end
    end
  end

  defp check(token, required, opts) do
    parts = String.split(token, ".")
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
        is_map(claims["cnf"]) and Map.has_key?(claims["cnf"], "jkt") -> refuse(401, "invalid_token", "DPoP-bound access tokens are not accepted here.", required, opts)
        true -> check_scopes(claims, required, opts)
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

  defp check_scopes(claims, required, opts) do
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
           client_id: claims["client_id"] || claims["azp"]
         }}

      missing ->
        refuse(403, "insufficient_scope",
          "The access token is missing the required scope(s): #{Enum.join(missing, " ")}.", required, opts)
    end
  end

  defp refuse(status, error, description, required, opts) do
    scope = if error in [nil, "insufficient_scope"], do: required, else: nil

    {:error,
     %{
       status: status,
       error: error,
       description: description,
       www_authenticate:
         build_www_authenticate(
           realm: opts[:realm],
           error: error,
           description: description,
           scope: scope,
           resource_metadata_url: opts[:resource_metadata_url]
         )
     }}
  end

  @doc """
  An RFC 6750 / RFC 9728 Bearer challenge. Without `:error` it is the bare
  "authentication required" challenge (no token was sent).
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

    if parts == [], do: "Bearer", else: "Bearer " <> Enum.join(parts, ", ")
  end

  @doc "The RFC 9728 protected-resource metadata document for your API."
  @spec protected_resource_metadata(String.t(), String.t(), [String.t()]) :: map()
  def protected_resource_metadata(resource, issuer, scopes_supported \\ []) do
    doc = %{
      "resource" => resource,
      "authorization_servers" => [String.trim_trailing(issuer, "/")],
      "bearer_methods_supported" => ["header"]
    }

    if scopes_supported == [], do: doc, else: Map.put(doc, "scopes_supported", scopes_supported)
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
    A Plug that protects an API with an Atlas-issued OAuth access token. A
    refusal halts with the verifier's status and `WWW-Authenticate` challenge; on
    success `conn.assigns.atlas_access_token` holds the verified token.

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

      case AtlasAuth.AccessToken.verify(authorization, opts) do
        {:ok, token} ->
          assign(conn, :atlas_access_token, token)

        {:error, refusal} ->
          conn
          |> put_resp_header("www-authenticate", refusal.www_authenticate)
          |> put_resp_content_type("application/json")
          |> send_resp(refusal.status, Jason.encode!(%{error: refusal.error || "unauthorized"}))
          |> halt()
      end
    end
  end
end
