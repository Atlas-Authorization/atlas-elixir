defmodule AtlasAuth.AccessTokenTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AtlasAuth.{AccessToken, Claims, TokenHelper, Verifier}

  @aud "https://api.test"

  setup_all do
    ec = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, ec_pub} = ec |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    keys = [Map.merge(ec_pub, %{"kid" => "ec-1", "alg" => "ES256"}) | TokenHelper.jwks()]
    {:ok, ec: ec, keys: keys}
  end

  defp opts(keys, extra \\ []) do
    TokenHelper.verify_opts(Keyword.merge([fetcher: fn _ -> {:ok, keys} end], extra))
  end

  defp es256(ec, claims, kid \\ "ec-1") do
    {_, compact} = ec |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => kid}, claims) |> JOSE.JWS.compact()
    compact
  end

  defp session(extra \\ %{}) do
    now = System.system_time(:second)
    Map.merge(%{"iss" => TokenHelper.issuer(), "sub" => "user_1", "iat" => now, "exp" => now + 300}, extra)
  end

  test "session verification accepts ES256, pins algorithms and reads app claims", %{ec: ec, keys: keys} do
    o = opts(keys)
    token = es256(ec, session(%{"app_roles" => ["support"], "app_permissions" => ["tickets:read"]}))
    assert {:ok, %Claims{} = c} = Verifier.verify(token, o)
    assert Claims.has_app_role?(c, "support")
    refute Claims.has_app_role?(c, "admin")
    assert Claims.has_app_permission?(c, "tickets:read")
    refute Claims.has_app_permission?(c, "tickets:write")
    assert {:ok, _} = Verifier.verify(TokenHelper.sign(), o)
    assert {:error, :invalid} = Verifier.verify(es256(ec, session(), TokenHelper.kid()), o)
    assert Verifier.signing_algs() == ["RS256", "ES256"]
  end

  defp access(extra \\ %{}) do
    session(Map.merge(%{"aud" => @aud, "token_use" => "access_token", "scope" => "read write", "client_id" => "oc_1"}, extra))
  end

  test "access tokens: accept, refuse and challenge", %{ec: ec, keys: keys} do
    o = opts(keys, audience: @aud, required_scopes: ["read"], resource_metadata_url: @aud <> "/.well-known/oauth-protected-resource")
    assert {:ok, %{subject: "user_1", client_id: "oc_1", scopes: ["read", "write"]}} =
             AccessToken.verify("Bearer " <> es256(ec, access()), o)

    assert {:error, %{status: 401, error: nil, www_authenticate: www}} = AccessToken.verify(nil, o)
    assert www == ~s(Bearer scope="read", resource_metadata="#{@aud}/.well-known/oauth-protected-resource")
    assert {:error, %{status: 400}} = AccessToken.verify("Basic abc", o)
    assert {:error, %{status: 401, www_authenticate: w}} = AccessToken.verify("Bearer " <> es256(ec, access(%{"aud" => "https://other.test"})), o)
    assert w =~ ~s(error="invalid_token")

    for extra <- [%{"token_use" => "session"}, %{"cnf" => %{"jkt" => "x"}}, %{"exp" => System.system_time(:second) - 600}] do
      assert {:error, _} = AccessToken.verify("Bearer " <> es256(ec, access(extra)), o)
    end

    assert {:error, %{status: 403, error: "insufficient_scope", www_authenticate: w}} =
             AccessToken.verify("Bearer " <> es256(ec, access(%{"scope" => "write"})), Keyword.put(o, :required_scopes, ["read", "admin"]))

    assert w =~ ~s(scope="read admin")
  end

  test "the RequireAccessToken plug halts with the challenge", %{ec: ec, keys: keys} do
    o = AtlasAuth.Plug.RequireAccessToken.init(opts(keys, audience: @aud))
    denied = conn(:get, "/items") |> AtlasAuth.Plug.RequireAccessToken.call(o)
    assert denied.halted and denied.status == 401
    assert [challenge] = get_resp_header(denied, "www-authenticate")
    assert String.starts_with?(challenge, "Bearer")

    ok =
      conn(:get, "/items")
      |> put_req_header("authorization", "Bearer " <> es256(ec, access()))
      |> AtlasAuth.Plug.RequireAccessToken.call(o)

    refute ok.halted
    assert ok.assigns.atlas_access_token.subject == "user_1"
  end

  test "helpers" do
    assert AccessToken.build_www_authenticate() == "Bearer"
    assert AccessToken.protected_resource_metadata_path("https://api.test/v1/") == "/.well-known/oauth-protected-resource/v1"
    assert %{"authorization_servers" => ["https://iss.test"]} = AccessToken.protected_resource_metadata(@aud, "https://iss.test/")
  end
end
