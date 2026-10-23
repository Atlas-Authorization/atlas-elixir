defmodule AtlasAuth.BySurfaceTest do
  # Not async: the introspection cache is one node-local ETS table.
  use ExUnit.Case, async: false

  alias AtlasAuth.{AccessToken, BotId, Constants, Introspection, TokenHelper}

  @aud "https://api.test"

  setup do
    Introspection.clear()
    calls = :counters.new(1, [])
    active = :atomics.new(1, [])
    :atomics.put(active, 1, 1)

    poster = fn url, headers, body ->
      :counters.add(calls, 1, 1)
      send(self(), {:introspect, url, headers, body})
      token = body |> URI.decode_query() |> Map.get("token")

      cond do
        token == "oat_down" ->
          {:ok, 500, ""}

        :atomics.get(active, 1) == 0 or token == "oat_dead" ->
          {:ok, 200, ~s({"active":false})}

        true ->
          iss = if token == "oat_foreign", do: "https://other.test", else: TokenHelper.issuer()

          {:ok, 200,
           Jason.encode!(%{
             active: true,
             iss: iss,
             sub: "u_1",
             aud: @aud,
             scope: "read",
             client_id: "oc_1",
             exp: System.system_time(:second) + 3600
           })}
      end
    end

    {:ok, calls: calls, active: active, poster: poster}
  end

  defp opts(poster, extra) do
    TokenHelper.verify_opts(
      Keyword.merge(
        [
          fetcher: fn _ -> {:ok, TokenHelper.jwks()} end,
          audience: @aud,
          introspection: [client_id: "oc_api", client_secret: "s3cret", poster: poster]
        ],
        extra
      )
    )
  end

  test "opaque tokens are introspected, cached and checked", %{
    calls: calls,
    active: active,
    poster: poster
  } do
    o = opts(poster, required_scopes: ["read"])
    assert {:ok, %{subject: "u_1", client_id: "oc_1"}} = AccessToken.verify("Bearer oat_live", o)
    assert_received {:introspect, url, headers, body}
    assert url == String.trim_trailing(TokenHelper.issuer(), "/") <> "/oauth2/introspect"
    assert {"authorization", "Basic " <> Base.encode64("oc_api:s3cret")} in headers
    assert URI.decode_query(body)["token_type_hint"] == "access_token"

    assert {:ok, _} = AccessToken.verify("Bearer oat_live", o)
    assert :counters.get(calls, 1) == 1

    assert {:error, %{status: 403, error: "insufficient_scope"}} =
             AccessToken.verify("Bearer oat_live", opts(poster, required_scopes: ["admin"]))

    assert {:error, %{status: 401}} = AccessToken.verify("Bearer oat_dead", o)
    n = :counters.get(calls, 1)
    AccessToken.verify("Bearer oat_dead", o)
    assert :counters.get(calls, 1) == n

    assert {:error, %{description: d1}} = AccessToken.verify("Bearer oat_foreign", o)
    assert d1 =~ "another authorization server"
    assert {:error, %{description: d2}} = AccessToken.verify("Bearer oat_down", o)
    assert d2 =~ "could not be validated"

    plain =
      TokenHelper.verify_opts(fetcher: fn _ -> {:ok, TokenHelper.jwks()} end, audience: @aud)

    assert {:error, %{description: d3}} = AccessToken.verify("Bearer oat_live", plain)
    assert d3 =~ "introspection"

    # introspect_jwts: a valid JWT is checked live too (here: revoked).
    now = System.system_time(:second)

    jwt =
      TokenHelper.sign(%{
        "iss" => TokenHelper.issuer(),
        "sub" => "u_2",
        "aud" => @aud,
        "exp" => now + 60,
        "iat" => now,
        "token_use" => "access_token"
      })

    assert {:ok, _} = AccessToken.verify("Bearer " <> jwt, plain)
    :atomics.put(active, 1, 0)

    live =
      opts(poster,
        introspection: [
          client_id: "oc_api",
          client_secret: "s3cret",
          poster: poster,
          introspect_jwts: true
        ]
      )

    assert {:error, %{status: 401}} = AccessToken.verify("Bearer " <> jwt, live)

    assert {:error, :missing_client_credentials} =
             Introspection.introspect("oat_x", TokenHelper.issuer(),
               client_id: "",
               client_secret: ""
             )
  end

  test "the introspection cache is bounded and never outlives exp" do
    hits = :counters.new(1, [])

    poster = fn _url, _headers, _body ->
      :counters.add(hits, 1, 1)
      {:ok, 200, ~s({"active":true,"exp":1800000005})}
    end

    o = [
      client_id: "a",
      client_secret: "b",
      poster: poster,
      cache_max: 2,
      now_ms: 1_800_000_000_000
    ]

    for t <- ["t1", "t2", "t3"],
        do: assert({:ok, %{}} = Introspection.introspect(t, "https://iss.test", o))

    assert Introspection.size() <= 2
    Introspection.introspect("t3", "https://iss.test", o)
    n = :counters.get(hits, 1)
    Introspection.introspect("t3", "https://iss.test", Keyword.put(o, :now_ms, 1_800_000_006_000))
    assert :counters.get(hits, 1) == n + 1
  end

  test "BotID attestations" do
    secret = String.duplicate("k", 32)
    {:ok, tok} = BotId.create_attestation(secret, false, ttl_seconds: 3600, now: 1_800_000_000)
    assert String.starts_with?(tok, BotId.prefix())
    [payload, sig] = tok |> String.replace_prefix(BotId.prefix(), "") |> String.split(".")

    assert sig ==
             :crypto.mac(:hmac, :sha256, secret, BotId.prefix() <> payload)
             |> Base.url_encode64(padding: false)

    p = payload |> Base.url_decode64!(padding: false) |> Jason.decode!()
    assert p["v"] == 1 and p["is_bot"] == false and p["verified_bot"] == false
    assert p["iat"] == 1_800_000_000 and p["exp"] - p["iat"] == 300
    assert String.length(p["jti"]) >= 20
    assert {:error, :secret_too_short} = BotId.create_attestation("short", false)
  end

  test "constants" do
    assert "captchafox" in Constants.captcha_providers()
    assert "vercel_botid" in Constants.captcha_providers()
    assert "commet" in Constants.billing_providers()
    assert Constants.webhook_session_updated() == "session.updated"
    assert Constants.webhook_user_reactivated() == "user.reactivated"
  end

  test "device approval: lookup, approve, deny, step-up refusal" do
    alias AtlasAuth.DeviceAuthorizations, as: D
    me = self()
    status = :atomics.new(1, [])
    :atomics.put(status, 1, 200)

    poster = fn url, headers, body ->
      send(me, {:device, url, headers, Jason.decode!(body)})

      case :atomics.get(status, 1) do
        200 -> {:ok, 200, ~s({"object":"device_authorization","id":"da_1","user_code":"WDJB-MJHT","client":{"name":"TV"}})}
        s -> {:ok, s, ~s({"errors":[{"code":"STEP_UP_REQUIRED","message":"Re-authenticate."}]})}
      end
    end

    opts = [frontend_api: "https://fapi.test/", session_token: "sess_jwt", publishable_key: "pk_x", poster: poster]
    assert {:ok, auth} = D.lookup(" wdjb mjht ", opts)
    assert_received {:device, "https://fapi.test/v1/client/me/device_authorizations/lookup", headers, %{"user_code" => "WDJB-MJHT"}}
    assert {"authorization", "Bearer sess_jwt"} in headers
    assert {"x-publishable-key", "pk_x"} in headers
    assert auth["client"]["name"] == "TV"
    assert {:ok, _} = D.approve(auth, opts)
    assert_received {:device, "https://fapi.test/v1/client/me/device_authorizations/da_1/approve", _, _}
    assert {:ok, _} = D.deny(auth, opts)
    assert_received {:device, "https://fapi.test/v1/client/me/device_authorizations/da_1/deny", _, _}
    :atomics.put(status, 1, 403)
    assert {:error, %{status: 403, code: "STEP_UP_REQUIRED"}} = D.approve(auth, opts)
    assert D.format_user_code("abc") == "abc"
    assert D.user_code_from_url("https://x.test/d?user_code=wdjbmjht") == "WDJB-MJHT"
    assert D.user_code_from_url("nope") == nil
  end
end
