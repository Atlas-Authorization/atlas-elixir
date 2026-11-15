defmodule AtlasAuth.Plug.RPTest do
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AtlasAuth.{OIDC, RP, TokenHelper}

  @issuer TokenHelper.issuer()
  @client "client_test_1"
  @redirect "https://app.example.com/auth/callback"

  setup do
    OIDC.reset_caches()
    nonce = :atomics.new(1, [])
    {:ok, nonce_ref} = Agent.start_link(fn -> nil end)

    http = fn _m, url, _h, _b ->
      cond do
        String.ends_with?(url, "/.well-known/openid-configuration") ->
          body = %{
            "issuer" => @issuer,
            "authorization_endpoint" => @issuer <> "/oauth2/authorize",
            "token_endpoint" => @issuer <> "/oauth2/token",
            "jwks_uri" => @issuer <> "/.well-known/jwks.json",
            "end_session_endpoint" => @issuer <> "/oauth2/logout"
          }

          {:ok, %{status: 200, headers: [], body: Jason.encode!(body)}}

        String.ends_with?(url, "/oauth2/token") ->
          now = System.system_time(:second)
          idt = TokenHelper.sign(%{"aud" => @client, "nonce" => Agent.get(nonce_ref, & &1), "auth_time" => now})
          {:ok, %{status: 200, headers: [], body: Jason.encode!(%{"id_token" => idt, "access_token" => "at", "expires_in" => 60})}}
      end
    end

    rp =
      RP.new(
        issuer: @issuer,
        client_id: @client,
        client_secret: "shh",
        redirect_uri: @redirect,
        secret: String.duplicate("k", 40),
        http: http,
        fetcher: TokenHelper.fetcher()
      )

    test_pid = self()

    opts =
      AtlasAuth.Plug.RP.init(
        rp: rp,
        on_signed_in: fn conn, user, _tokens, _result ->
          send(test_pid, {:signed_in, user})
          put_resp_cookie(conn, "app_session", "sess-for-" <> user.sub)
        end,
        on_sign_out: fn _conn -> [set_cookies: ["app_session=; Max-Age=0"]] end
      )

    _ = nonce
    {:ok, opts: opts, nonce_ref: nonce_ref}
  end

  test "init/1 requires :rp and :on_signed_in" do
    assert_raise ArgumentError, fn -> AtlasAuth.Plug.RP.init([]) end
  end

  test "sign-in redirects to authorize with the flow cookie; the callback signs in and redirects", %{opts: opts, nonce_ref: nonce_ref} do
    conn = conn(:get, "/auth/sign-in?return_to=/dash") |> AtlasAuth.Plug.RP.call(opts)
    assert conn.status == 302 and conn.halted
    [location] = get_resp_header(conn, "location")
    assert String.starts_with?(location, @issuer <> "/oauth2/authorize?")
    [flow_cookie] = get_resp_header(conn, "set-cookie")
    q = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    Agent.update(nonce_ref, fn _ -> q["nonce"] end)

    cb =
      conn(:get, "/auth/callback?code=c1&state=" <> q["state"])
      |> put_req_header("cookie", flow_cookie |> String.split(";") |> hd())
      |> AtlasAuth.Plug.RP.call(opts)

    assert cb.status == 302
    assert get_resp_header(cb, "location") == ["/dash"]
    assert_received {:signed_in, %{sub: "user_2abc"}}
    cookies = get_resp_header(cb, "set-cookie")
    assert Enum.any?(cookies, &String.starts_with?(&1, "app_session=sess-for-user_2abc"))
    assert Enum.any?(cookies, &String.contains?(&1, "atlas_oidc=;"))
  end

  test "a failed callback answers 400 and clears the flow cookie", %{opts: opts} do
    conn = conn(:get, "/auth/callback?code=c&state=x") |> AtlasAuth.Plug.RP.call(opts)
    assert conn.status == 400
    assert Enum.any?(get_resp_header(conn, "set-cookie"), &String.contains?(&1, "Max-Age=0"))
  end

  test "sign-out redirects to the end-session endpoint with the app's cookie clearing header", %{opts: opts} do
    conn = conn(:post, "/auth/sign-out") |> AtlasAuth.Plug.RP.call(opts)
    assert conn.status == 302
    assert [location] = get_resp_header(conn, "location")
    assert String.starts_with?(location, @issuer <> "/oauth2/logout")
    assert "app_session=; Max-Age=0" in get_resp_header(conn, "set-cookie")
  end

  test "other paths pass through untouched", %{opts: opts} do
    conn = conn(:get, "/dashboard") |> AtlasAuth.Plug.RP.call(opts)
    refute conn.halted
    assert conn.status == nil
  end
end
