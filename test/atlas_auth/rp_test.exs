defmodule AtlasAuth.RPTest do
  use ExUnit.Case, async: false

  alias AtlasAuth.{OIDC, RP, TokenHelper}

  @issuer TokenHelper.issuer()
  @client "client_test_1"
  @redirect "https://app.example.com/auth/callback"
  @secret String.duplicate("s", 40)

  setup do
    OIDC.reset_caches()
    {:ok, store} = RP.SidStore.Memory.start_link([])
    {:ok, calls: Agent.start_link(fn -> [] end) |> elem(1), store: store}
  end

  # A fake issuer + Atlas API. `tokens` builds the token endpoint's answer from the form it received.
  defp http(calls, opts \\ []) do
    fn method, url, headers, body ->
      Agent.update(calls, &[{method, url, headers, body} | &1])

      cond do
        String.ends_with?(url, "/.well-known/openid-configuration") ->
          json(200, %{
            "issuer" => @issuer,
            "authorization_endpoint" => @issuer <> "/oauth2/authorize",
            "token_endpoint" => @issuer <> "/oauth2/token",
            "jwks_uri" => @issuer <> "/.well-known/jwks.json",
            "end_session_endpoint" => @issuer <> "/oauth2/logout"
          })

        String.ends_with?(url, "/oauth2/token") ->
          form = URI.decode_query(body)
          fun = opts[:token] || fn _ -> json(400, %{"error" => "invalid_grant"}) end
          fun.(form)

        String.contains?(url, "/v1/sessions/") ->
          (opts[:api] || fn _, _ -> json(200, %{"idle_expires_at" => "2030-01-01T00:00:00Z"}) end).(method, url)

        String.contains?(url, "/oauth2/session/") ->
          (opts[:app] || fn _, _ -> json(200, %{}) end).(method, url)

        true ->
          json(404, %{})
      end
    end
  end

  defp json(status, map), do: {:ok, %{status: status, headers: [], body: Jason.encode!(map)}}

  defp rp(calls, extra \\ []) do
    RP.new(
      [
        issuer: @issuer,
        client_id: @client,
        client_secret: "shh",
        redirect_uri: @redirect,
        secret: @secret,
        http: http(calls, extra[:fake] || []),
        fetcher: TokenHelper.fetcher()
      ] ++ Keyword.delete(extra, :fake)
    )
  end

  defp query_of(url), do: url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  defp cookie_value(set_cookie), do: set_cookie |> String.split(";") |> hd()

  defp id_token(nonce, extra \\ %{}) do
    now = System.system_time(:second)

    TokenHelper.sign(
      Map.merge(%{"aud" => @client, "nonce" => nonce, "auth_time" => now, "email" => "a@example.com", "email_verified" => true}, extra)
    )
  end

  defp token_endpoint(nonce_ref, extra \\ %{}) do
    fn _form ->
      json(200, %{"id_token" => id_token(Agent.get(nonce_ref, & &1), extra), "access_token" => "at_1", "expires_in" => 3600, "refresh_token" => "rt_1"})
    end
  end

  describe "start/3" do
    test "builds an authorize URL with PKCE S256, state, nonce and a sealed flow cookie", %{calls: calls} do
      {:ok, %{location: url, cookies: [cookie]}} = RP.start(rp(calls), %{"return_to" => "/settings", "login_hint" => "a@example.com"})
      q = query_of(url)
      assert String.starts_with?(url, @issuer <> "/oauth2/authorize?")
      assert q["response_type"] == "code" and q["client_id"] == @client and q["redirect_uri"] == @redirect
      assert q["code_challenge_method"] == "S256" and q["login_hint"] == "a@example.com"
      assert q["scope"] == "openid profile email"
      assert is_binary(q["state"]) and is_binary(q["nonce"]) and is_binary(q["code_challenge"])
      refute Map.has_key?(q, "return_to")
      assert cookie =~ "atlas_oidc=s1."
      assert cookie =~ "Path=/auth/callback" and cookie =~ "HttpOnly" and cookie =~ "SameSite=Lax" and cookie =~ "Secure"
    end

    test "a bad return_to is dropped, forward_params pass through, owned params do not", %{calls: calls} do
      rp = rp(calls, forward_params: ["ref"])
      {:ok, %{location: url}} = RP.start(rp, %{"return_to" => "//evil.example", "ref" => "abc", "state" => "x"})
      q = query_of(url)
      assert q["ref"] == "abc"
      assert q["state"] != "x"
    end

    test "new/1 refuses a short secret and forwarding an owned parameter" do
      assert_raise ArgumentError, ~r/secret/, fn -> RP.new(issuer: @issuer, client_id: @client, redirect_uri: @redirect, secret: "short") end

      assert_raise ArgumentError, ~r/forward_params/, fn ->
        RP.new(issuer: @issuer, client_id: @client, redirect_uri: @redirect, secret: @secret, forward_params: ["state"])
      end
    end
  end

  describe "callback/3" do
    test "verifies state, exchanges the code with PKCE and Basic client auth, and verifies the ID token", %{calls: calls} do
      {:ok, nonce_ref} = Agent.start_link(fn -> nil end)
      rp = rp(calls, fake: [token: token_endpoint(nonce_ref)])
      {:ok, %{location: url, cookies: [cookie]}} = RP.start(rp, %{"return_to" => "/settings"})
      q = query_of(url)
      Agent.update(nonce_ref, fn _ -> q["nonce"] end)

      assert {:ok, %{user: user, tokens: tokens, redirect: redirect}} =
               RP.callback(rp, %{"code" => "c1", "state" => q["state"]}, cookie_value(cookie))

      assert user.sub == "user_2abc" and user.sid == "sess_2def" and user.email == "a@example.com" and user.email_verified
      assert tokens.access_token == "at_1" and tokens.refresh_token == "rt_1"
      assert redirect.location == "/settings"
      assert [clear] = redirect.cookies
      assert clear =~ "Max-Age=0"

      {_, _, headers, body} = calls |> Agent.get(& &1) |> Enum.find(fn {_, u, _, _} -> String.ends_with?(u, "/oauth2/token") end)
      form = URI.decode_query(body)
      assert form["grant_type"] == "authorization_code" and form["code"] == "c1" and form["redirect_uri"] == @redirect
      assert is_binary(form["code_verifier"])
      assert {"authorization", "Basic " <> basic} = List.keyfind(headers, "authorization", 0)
      assert Base.decode64!(basic) == "client_test_1:shh"
    end

    test "refuses a wrong state, a missing cookie and a tampered cookie", %{calls: calls} do
      rp = rp(calls)
      {:ok, %{cookies: [cookie]}} = RP.start(rp)
      assert {:error, %OIDC.Error{code: :state_mismatch, clear_cookie: clear}} = RP.callback(rp, %{"code" => "c", "state" => "nope"}, cookie_value(cookie))
      assert clear =~ "Max-Age=0"
      assert {:error, %OIDC.Error{code: :state_mismatch}} = RP.callback(rp, %{"code" => "c", "state" => "x"}, nil)
      good = cookie_value(cookie)
      tampered = String.slice(good, 0..-2//1) <> if(String.ends_with?(good, "A"), do: "B", else: "A")
      assert {:error, %OIDC.Error{code: :state_mismatch}} = RP.callback(rp, %{"code" => "c", "state" => "x"}, tampered)
    end

    test "an authorization error becomes access_denied; an ID token with another nonce is refused", %{calls: calls} do
      {:ok, nonce_ref} = Agent.start_link(fn -> "not-the-nonce" end)
      rp = rp(calls, fake: [token: token_endpoint(nonce_ref)])
      {:ok, %{location: url, cookies: [cookie]}} = RP.start(rp)
      state = query_of(url)["state"]

      assert {:error, %OIDC.Error{code: :access_denied, oauth_error: "access_denied"}} =
               RP.callback(rp, %{"error" => "access_denied", "state" => state}, cookie_value(cookie))

      assert {:error, %OIDC.Error{code: :invalid_token, message: msg}} = RP.callback(rp, %{"code" => "c", "state" => state}, cookie_value(cookie))
      assert msg =~ "nonce"
    end

    test "an ID token for another audience is refused", %{calls: calls} do
      {:ok, nonce_ref} = Agent.start_link(fn -> nil end)
      rp = rp(calls, fake: [token: token_endpoint(nonce_ref, %{"aud" => "someone_else"})])
      {:ok, %{location: url, cookies: [cookie]}} = RP.start(rp)
      q = query_of(url)
      Agent.update(nonce_ref, fn _ -> q["nonce"] end)
      assert {:error, %OIDC.Error{code: :invalid_token}} = RP.callback(rp, %{"code" => "c", "state" => q["state"]}, cookie_value(cookie))
    end
  end

  describe "require_recent_auth/3" do
    test "passes inside the window and redirects with max_age and the expected sub outside it", %{calls: calls} do
      now = 1_900_000_000_000
      rp = rp(calls, now_ms: now)
      assert :ok = RP.require_recent_auth(rp, 300, sub: "u1", auth_time: div(now, 1000) - 100)

      assert {:redirect, %{location: url, cookies: [_]}} =
               RP.require_recent_auth(rp, 300, sub: "u1", auth_time: div(now, 1000) - 1000, return_to: "/billing")

      assert query_of(url)["max_age"] == "300"
      refute Map.has_key?(query_of(url), "prompt")

      assert {:redirect, %{location: url0}} = RP.require_recent_auth(rp, 0, sub: "u1", auth_time: div(now, 1000) - 3600)
      assert query_of(url0)["prompt"] == "login"
      assert :ok = RP.require_recent_auth(rp, 0, sub: "u1", auth_time: div(now, 1000) - 10)
    end
  end

  describe "touch_if_due/3, revoke_session/2, end_app_session/2" do
    test "skips inside the interval, touches, and maps session ends", %{calls: calls} do
      now = 1_900_000_000_000
      ok = rp(calls, secret_key: "sk_test_x", now_ms: now)
      assert {:skipped, last} = RP.touch_if_due(ok, "sess_1", now - 1000)
      assert last == now - 1000
      assert {:touched, %{last_touched_at: ^now, idle_expires_at: "2030-01-01T00:00:00Z"}} = RP.touch_if_due(ok, "sess_1", nil)

      revoked = rp(calls, secret_key: "sk_test_x", fake: [api: fn _, _ -> json(409, %{"errors" => [%{"code" => "SESSION_REVOKED"}]}) end])
      assert {:ended, :revoked} = RP.touch_if_due(revoked, "sess_1", nil)
      gone = rp(calls, secret_key: "sk_test_x", fake: [api: fn _, _ -> json(404, %{}) end])
      assert {:ended, :not_found} = RP.touch_if_due(gone, "sess_1", nil)
      assert {:ok, :not_found} = RP.revoke_session(gone, "sess_1")
      denied = rp(calls, secret_key: "sk_test_x", fake: [api: fn _, _ -> json(403, %{"errors" => [%{"code" => "INSUFFICIENT_SCOPE", "message" => "no"}]}) end])
      assert {:error, %{status: 403, code: "INSUFFICIENT_SCOPE"}} = RP.touch_if_due(denied, "sess_1", nil)
    end

    test "without a secret key the app's own sign-in is touched and ended with the client credentials", %{calls: calls} do
      rp = rp(calls, fake: [app: fn _, url -> if String.ends_with?(url, "/touch"), do: json(200, %{"idle_expires_at" => 1_900_000_000_000}), else: json(404, %{"error" => "session_not_found"}) end])
      assert {:touched, %{idle_expires_at: iso}} = RP.touch_if_due(rp, "sess_1", nil)
      assert iso =~ "T"
      assert {:ok, :not_found} = RP.end_app_session(rp, "sess_1")
    end
  end

  describe "sign_out/2" do
    test "revokes server-side first, then redirects to the end-session endpoint", %{calls: calls} do
      rp = rp(calls, secret_key: "sk_test_x", post_logout_redirect_uri: "https://app.example.com/")
      assert {:ok, %{location: url, cookies: ["sid=; Max-Age=0"]}} = RP.sign_out(rp, sid: "sess_1", id_token: "idt", state: "st", set_cookies: ["sid=; Max-Age=0"])
      q = query_of(url)
      assert String.starts_with?(url, @issuer <> "/oauth2/logout?")
      assert q["id_token_hint"] == "idt" and q["client_id"] == @client and q["state"] == "st"
      assert Enum.any?(Agent.get(calls, & &1), fn {m, u, _, _} -> m == :post and String.ends_with?(u, "/v1/sessions/sess_1/revoke") end)
    end

    test "server_sign_out ends everything in one call and skips the logout hop", %{calls: calls} do
      rp = rp(calls, secret_key: "sk_test_x", server_sign_out: true, post_logout_redirect_uri: "/bye", fake: [api: fn _, _ -> json(200, %{}) end])
      fake = http(calls, api: fn _, _ -> json(200, %{}) end)
      rp = %{rp | http: fn m, u, h, b -> if String.contains?(u, "/oauth_clients/"), do: json(200, %{}), else: fake.(m, u, h, b) end}
      assert {:ok, %{location: "/bye"}} = RP.sign_out(rp, sid: "sess_1")
    end
  end

  describe "sid store" do
    test "bind and the back-channel handler take the bound sessions, restoring them when the handler fails", %{calls: calls, store: store} do
      rp = rp(calls, sid_store: {RP.SidStore.Memory, store}, now_ms: 1_900_000_000_000)
      :ok = RP.bind_session(rp, "sid_1", "app_a", 1_900_000_100_000)
      :ok = RP.bind_session(rp, "sid_1", "app_b", 1_900_000_100_000)
      handler = RP.backchannel_handler(rp, fn ids, _claims -> send(self(), {:ended, Enum.sort(ids)}) && :ok end)
      handler.(%{sid: "sid_1", sub: "u"})
      assert_received {:ended, ["app_a", "app_b"]}
      assert RP.SidStore.take({RP.SidStore.Memory, store}, "sid_1") == []

      :ok = RP.bind_session(rp, "sid_2", "app_c", 1_900_000_100_000)
      failing = RP.backchannel_handler(rp, fn _ids, _claims -> {:error, :nope} end)
      assert {:error, :nope} = failing.(%{sid: "sid_2", sub: "u"})
      assert RP.SidStore.take({RP.SidStore.Memory, store}, "sid_2") == ["app_c"]
    end
  end

  test "safe_return_to?/1 accepts plain paths only" do
    assert OIDC.safe_return_to?("/a/b?c=1")
    refute OIDC.safe_return_to?("//evil.example")
    refute OIDC.safe_return_to?("/\\evil")
    refute OIDC.safe_return_to?("https://evil.example")
    refute OIDC.safe_return_to?("/a\nb")
  end
end
