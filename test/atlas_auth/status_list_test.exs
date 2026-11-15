defmodule AtlasAuth.StatusListTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{SidRevocation, StatusList}

  @issuer "https://atlas.test"
  @now_sec 1_800_000_000
  @now_ms @now_sec * 1000 + 10_000

  @algs [
    {"RS256", {:rsa, 2048}},
    {"PS256", {:rsa, 2048}},
    {"ES256", {:ec, :secp256r1}},
    {"ES384", {:ec, :secp384r1}},
    {"EdDSA", {:okp, :Ed25519}}
  ]

  defp hash_of(sid), do: binary_part(:crypto.hash(:sha256, sid), 0, 8)

  defp keys(jwk, alg) do
    {_, m} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    [Map.merge(m, %{"kid" => "k1", "alg" => alg, "use" => "sig"})]
  end

  defp token(jwk, alg, sids, over \\ %{}, header \\ %{}) do
    hashes = sids |> Enum.map(&hash_of/1) |> Enum.sort()

    claims =
      Map.merge(
        %{
          "iss" => @issuer, "sub" => "session-status-list", "aud" => "atlas:session-status-list", "token_use" => "session_status_list",
          "iat" => @now_sec, "nbf" => @now_sec - 5, "exp" => @now_sec + 120, "since" => (@now_sec - 3600) * 1000,
          "window_seconds" => 3600, "hash_bytes" => 8, "count" => length(hashes), "truncated" => false,
          "h" => Base.url_encode64(Enum.join(hashes), padding: false)
        },
        over
      )

    {_, t} = jwk |> JOSE.JWT.sign(Map.merge(%{"alg" => alg, "kid" => "k1", "typ" => "statuslist+jwt"}, header), claims) |> JOSE.JWS.compact()
    t
  end

  defp opts(keys, extra \\ []) do
    name = :"sl_cache_#{System.unique_integer([:positive])}"
    {:ok, _} = AtlasAuth.JWKSCache.start_link(name: name)
    [jwks_url: "https://atlas.test/jwks/#{System.unique_integer([:positive])}", issuer: @issuer, fetcher: fn _ -> {:ok, keys} end, cache: name, now_ms: @now_ms] ++ extra
  end

  for {alg, gen} <- @algs do
    test "#{alg}: verifies and finds exactly the listed sessions" do
      jwk = JOSE.JWK.generate_key(unquote(Macro.escape(gen)))
      {:ok, list} = StatusList.verify(token(jwk, unquote(alg), ["sess_a", "sess_b", "sess_c"]), opts(keys(jwk, unquote(alg))))
      assert list.count == 3 and list.truncated == false
      for s <- ["sess_a", "sess_b", "sess_c"], do: assert(StatusList.has?(list, s))
      refute StatusList.has?(list, "sess_d")
      assert list.expires_at == (@now_sec + 120) * 1000
    end
  end

  test "an empty list verifies" do
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
    assert {:ok, %{count: 0}} = StatusList.verify(token(jwk, "ES256", []), opts(keys(jwk, "ES256")))
  end

  test "a bad signature, wrong issuer, expiry, wrong type and wrong kind of token are refused" do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    other = JOSE.JWK.generate_key({:rsa, 2048})
    o = opts(keys(jwk, "RS256"))
    assert {:error, :bad_signature} = StatusList.verify(token(other, "RS256", ["a"]), o)
    assert {:error, :bad_claims} = StatusList.verify(token(jwk, "RS256", ["a"], %{"iss" => "https://evil.test"}), o)
    assert {:error, :expired} = StatusList.verify(token(jwk, "RS256", ["a"], %{"exp" => @now_sec - 1000}), o)
    assert {:error, :bad_claims} = StatusList.verify(token(jwk, "RS256", ["a"], %{"token_use" => "session"}), o)
    assert {:error, :bad_claims} = StatusList.verify(token(jwk, "RS256", ["a"], %{"count" => 5}), o)
    assert {:error, :unsupported} = StatusList.verify(token(jwk, "RS256", ["a"], %{}, %{"typ" => "JWT"}), o)
    assert {:error, :malformed} = StatusList.verify("not-a-jwt", o)
  end

  describe "SidRevocation source: :status_list" do
    defp start(jwk, alg, fetch_list, fetch_page) do
      {:ok, c} = Agent.start_link(fn -> @now_ms end)
      o = opts(keys(jwk, alg))
      {:ok, pid} = SidRevocation.start_link([source: :status_list, fetch_status_list: fetch_list, fetch_page: fetch_page, now_ms: fn -> Agent.get(c, & &1) end] ++ Keyword.take(o, [:jwks_url, :issuer, :fetcher, :cache]))
      pid
    end

    test "answers from the signed list without touching the feed" do
      jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
      t = token(jwk, "EdDSA", ["s1"])
      pid = start(jwk, "EdDSA", fn _ -> {:ok, %{"token" => t}} end, fn _ -> flunk("the feed must not be read") end)
      assert {:error, :revoked} = SidRevocation.check(pid, "s1")
      assert :ok = SidRevocation.check(pid, "s2")
      assert SidRevocation.revoked?(pid, "s1")
    end

    test "a truncated list, a bad signature and a failing endpoint fall back to the feed" do
      jwk = JOSE.JWK.generate_key({:ec, :secp384r1})
      feed = fn _ -> {:ok, %{"data" => [%{"sid" => "f1", "revoked_at" => @now_ms}], "has_more" => false, "server_time" => @now_ms}} end

      truncated = token(jwk, "ES384", ["s1"], %{"truncated" => true})
      pid = start(jwk, "ES384", fn _ -> {:ok, %{"token" => truncated}} end, feed)
      assert {:error, :revoked} = SidRevocation.check(pid, "s1")
      assert {:error, :revoked} = SidRevocation.check(pid, "f1")
      assert :ok = SidRevocation.check(pid, "other")

      forged = token(JOSE.JWK.generate_key({:ec, :secp384r1}), "ES384", ["zzz"])
      pid2 = start(jwk, "ES384", fn _ -> {:ok, %{"token" => forged}} end, feed)
      assert {:error, :revoked} = SidRevocation.check(pid2, "f1")

      pid3 = start(jwk, "ES384", fn _ -> {:error, :down} end, feed)
      assert {:error, :revoked} = SidRevocation.check(pid3, "f1")
    end
  end
end
