defmodule AtlasAuth.BetterAuthTest do
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AtlasAuth.{BetterAuth, TokenHelper}

  @tokens ~s({"object":"session_tokens","session_id":"sess_1","user_id":"user_1","jwt":"eyJ.jwt","refresh_token":"rt_1","expires_in":60})

  # A poster that records every call to the test process and answers `{status, body}`.
  defp poster(status, body) do
    me = self()

    fn url, headers, req_body ->
      send(me, {:post, url, headers, Jason.decode!(req_body)})
      {:ok, status, body}
    end
  end

  defp refusal(status, outcome),
    do:
      {status,
       Jason.encode!(%{
         errors: [%{code: "REFUSED", message: "no", meta: %{bridge_outcome: outcome}}]
       })}

  defp opts(status, body, extra \\ []),
    do:
      Keyword.merge(
        [
          secret_key: "sk_test_secret",
          api_url: "https://api.atlas.test",
          poster: poster(status, body)
        ],
        extra
      )

  describe "exchange" do
    test "posts the token with the secret key and forwards the end user" do
      assert {:ok, %{"jwt" => "eyJ.jwt"}} =
               BetterAuth.exchange(
                 "tok.sig",
                 opts(200, @tokens, client_ip: "203.0.113.9", user_agent: "UA/1", remember: false)
               )

      assert_received {:post, url, headers, body}
      assert url == "https://api.atlas.test/v1/migrations/better_auth/exchange"
      assert {"authorization", "Bearer sk_test_secret"} in headers
      assert {"x-atlas-client-ip", "203.0.113.9"} in headers
      assert {"x-atlas-client-user-agent", "UA/1"} in headers
      assert body == %{"token" => "tok.sig", "remember" => false}

      BetterAuth.exchange("tok", opts(200, @tokens))
      assert_received {:post, _, headers, %{"token" => "tok"} = body}
      refute Map.has_key?(body, "remember")
      refute Enum.any?(headers, fn {k, _} -> k == "x-atlas-client-ip" end)
    end

    test "a refusal carries status, code and meta; a secret key is required" do
      {status, body} = refusal(400, "reused")

      assert {:error, %{status: 400, code: "REFUSED", meta: %{"bridge_outcome" => "reused"}}} =
               BetterAuth.exchange("t", opts(status, body))

      prior = System.get_env("ATLAS_SECRET_KEY")
      System.delete_env("ATLAS_SECRET_KEY")

      try do
        assert_raise ArgumentError, ~r/secret_key/, fn ->
          BetterAuth.exchange("t", poster: poster(200, @tokens))
        end
      after
        if prior, do: System.put_env("ATLAS_SECRET_KEY", prior)
      end
    end

    test "results are classified" do
      assert {:session,
              %{
                jwt: "eyJ.jwt",
                refresh_token: "rt_1",
                session_id: "sess_1",
                user_id: "user_1",
                expires_in: 60
              }} = BetterAuth.exchange_session("t", opts(200, @tokens))

      assert {:needs_mfa, %{attempt_id: "sia_1", status: "needs_mfa_enrollment"}} =
               BetterAuth.exchange_session(
                 "t",
                 opts(
                   200,
                   ~s({"object":"sign_in_attempt","id":"sia_1","status":"needs_mfa_enrollment"})
                 )
               )

      for o <- ~w(closed invalid signature_invalid expired reused user_unavailable) do
        {status, body} = refusal(400, o)
        assert {:refused, atom, 400} = BetterAuth.exchange_session("t", opts(status, body))
        assert Atom.to_string(atom) == o
      end

      {_, body} = refusal(429, "rate_limited")
      assert {:refused, :rate_limited, 429} = BetterAuth.exchange_session("t", opts(429, body))

      assert {:refused, :unavailable, 502} =
               BetterAuth.exchange_session("t", opts(502, "bad gateway"))

      {_, body} = refusal(403, "brand_new")
      assert {:refused, :unavailable, 403} = BetterAuth.exchange_session("t", opts(403, body))

      assert {:refused, :unavailable, 200} =
               BetterAuth.exchange_session("t", opts(200, ~s({"object":"weird"})))

      down = [secret_key: "sk", poster: fn _, _, _ -> {:error, :econnrefused} end]
      assert {:refused, :unavailable, 0} = BetterAuth.exchange_session("t", down)

      assert BetterAuth.final?(:reused) and not BetterAuth.final?(:closed) and
               not BetterAuth.final?(:rate_limited)
    end
  end

  describe "cookies and decisions" do
    test "cookie names and reading" do
      assert BetterAuth.cookie_names().session_token == [
               "__Secure-better-auth.session_token",
               "better-auth.session_token"
             ]

      assert length(BetterAuth.cookie_names("myapp").all) == 8
      header = "x=1; better-auth.session_token=plain; __Secure-better-auth.session_token=secure"
      assert BetterAuth.read_session_cookie(header) == "secure"

      assert BetterAuth.read_session_cookie("myapp.session_token=m", cookie_prefix: "myapp") ==
               "m"

      assert BetterAuth.read_session_cookie(%{"sid" => "s"}, cookie_name: "sid") == "s"
      assert BetterAuth.read_session_cookie(nil) == nil

      assert BetterAuth.client_ip_from_headers([{"x-forwarded-for", " 198.51.100.1, 10.0.0.1"}]) ==
               "198.51.100.1"

      assert BetterAuth.client_ip_from_headers(%{"X-Real-IP" => "10.0.0.2"}) == "10.0.0.2"
      assert BetterAuth.client_ip_from_headers([]) == nil
    end

    test "no Better Auth cookie, or an Atlas session already present, means no call" do
      o = opts(200, @tokens)
      assert %{action: :none, cookies: []} = BetterAuth.decide(nil, o)
      assert %{action: :none} = BetterAuth.decide("better-auth.session_token=t; __session=eyJ", o)
      refute_received {:post, _, _, _}
    end

    test "signed in sets the Atlas cookies and clears Better Auth's" do
      d =
        BetterAuth.decide(
          "myapp.session_token=tok",
          opts(200, @tokens, cookie_prefix: "myapp", cookie_domain: ".example.com")
        )

      assert d.action == :signed_in and BetterAuth.redirect?(d)
      set = Enum.map(d.cookies, &BetterAuth.serialize_cookie/1)
      assert Enum.at(set, 0) == "__session=eyJ.jwt; Path=/; Secure; SameSite=Lax"
      assert Enum.at(set, 1) == "__atlas_rt=rt_1; Path=/; HttpOnly; Secure; SameSite=Lax"

      assert "myapp.session_token=; Path=/; Domain=.example.com; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT" in set

      assert "__Secure-myapp.session_token=; Path=/; Domain=.example.com; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure" in set

      insecure = BetterAuth.decision_for({:session, d.session}, secure: false)

      assert BetterAuth.serialize_cookie(hd(insecure.cookies)) ==
               "__session=eyJ.jwt; Path=/; SameSite=Lax"
    end

    test "refusals clear only when final; MFA carries the attempt" do
      {s, b} = refusal(400, "expired")
      d = BetterAuth.decide("sid=t", opts(s, b, cookie_name: "sid"))
      assert d.action == :refused and d.outcome == :expired and BetterAuth.redirect?(d)
      assert Enum.any?(d.cookies, &(&1.name == "__Secure-sid"))

      {s, b} = refusal(403, "closed")
      d = BetterAuth.decide("better-auth.session_token=t", opts(s, b))
      assert d.cookies == [] and not BetterAuth.redirect?(d)

      assert BetterAuth.continuation_url(
               "/sign-in?next=%2Fd&__atlas_status=x#top",
               "sia 1",
               "needs_second_factor"
             ) ==
               "/sign-in?next=%2Fd&__atlas_attempt=sia+1&__atlas_status=needs_second_factor#top"
    end
  end

  describe "AtlasAuth.Plug.BetterAuthBridge" do
    defp run(conn, status, body, extra \\ []) do
      AtlasAuth.Plug.BetterAuthBridge.call(
        conn,
        AtlasAuth.Plug.BetterAuthBridge.init(opts(status, body, extra))
      )
    end

    test "exchanges and redirects to the same URL with the cookies" do
      conn =
        conn(:get, "/dash?tab=1")
        |> put_req_header("cookie", "better-auth.session_token=tok.sig")
        |> put_req_header("x-forwarded-for", "203.0.113.9")
        |> put_req_header("user-agent", "Browser/1")
        |> run(200, @tokens)

      assert conn.halted and conn.status == 307
      assert get_resp_header(conn, "location") == ["/dash?tab=1"]
      cookies = get_resp_header(conn, "set-cookie")
      assert Enum.any?(cookies, &String.starts_with?(&1, "__session=eyJ.jwt;"))
      assert Enum.any?(cookies, &String.starts_with?(&1, "better-auth.session_token=;"))
      assert_received {:post, _, headers, _}
      assert {"x-atlas-client-ip", "203.0.113.9"} in headers
      assert {"x-atlas-client-user-agent", "Browser/1"} in headers
    end

    test "uses remote_ip without proxy headers, or when they are not trusted" do
      conn(:get, "/")
      |> Map.put(:remote_ip, {198, 51, 100, 7})
      |> put_req_header("cookie", "better-auth.session_token=t")
      |> put_req_header("x-forwarded-for", "1.2.3.4")
      |> run(200, @tokens, trust_forwarded_for: false)

      assert_received {:post, _, headers, _}
      assert {"x-atlas-client-ip", "198.51.100.7"} in headers
    end

    test "passes through on POST, without a cookie, and on a non-final refusal" do
      for conn <- [
            conn(:post, "/dash") |> put_req_header("cookie", "better-auth.session_token=t"),
            conn(:get, "/dash")
          ] do
        refute run(conn, 200, @tokens).halted
      end

      refute_received {:post, _, _, _}
      {s, b} = refusal(403, "closed")

      conn =
        conn(:get, "/") |> put_req_header("cookie", "better-auth.session_token=t") |> run(s, b)

      refute conn.halted
      assert get_resp_header(conn, "set-cookie") == []
    end

    test "a second factor goes to the sign-in page" do
      conn =
        conn(:get, "/dash")
        |> put_req_header("cookie", "better-auth.session_token=t")
        |> run(200, ~s({"object":"sign_in_attempt","id":"sia_1","status":"needs_second_factor"}),
          sign_in_url: "/sign-in"
        )

      assert conn.status == 307

      assert get_resp_header(conn, "location") == [
               "/sign-in?__atlas_attempt=sia_1&__atlas_status=needs_second_factor"
             ]
    end

    test "AtlasAuth.Plug runs the bridge first when asked" do
      bridge = [poster: poster(200, @tokens), api_url: "https://api.atlas.test"]

      plug_opts =
        TokenHelper.verify_opts(secret_key: "sk_test_secret", better_auth_bridge: bridge)

      conn =
        conn(:get, "/")
        |> put_req_header("cookie", "better-auth.session_token=t")
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(plug_opts))

      assert conn.halted and conn.status == 307
      assert_received {:post, _, headers, _}
      assert {"authorization", "Bearer sk_test_secret"} in headers

      # With an Atlas session the bridge does nothing and the plug verifies as usual.
      token = TokenHelper.sign()

      conn =
        conn(:get, "/")
        |> put_req_header("cookie", "better-auth.session_token=t; __session=" <> token)
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(plug_opts))

      refute conn.halted
      assert conn.assigns.atlas_authenticated? == true
    end
  end
end
