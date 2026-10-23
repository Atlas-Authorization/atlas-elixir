defmodule AtlasAuth.DPoPTest do
  # DPoP (RFC 9449) on the access-token verifier: the same vectors as the
  # TypeScript @atlasauth/backend suite, plus every other refusal path. Keys are
  # generated per run; the proofs are genuine ES256 / RS256 / PS256 / EdDSA
  # JWSs, signed with :crypto directly (independent of the JOSE verification).
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AtlasAuth.{AccessToken, DPoP, TokenHelper}
  alias AtlasAuth.DPoP.{HmacNonce, MemoryReplayStore}

  @api "https://api.example.com/mcp"
  @meta "https://api.example.com/.well-known/oauth-protected-resource/mcp"

  setup_all do
    {:ok, keys: TokenHelper.jwks()}
  end

  defp b64(bin), do: Base.url_encode64(bin, padding: false)
  defp unb64(s), do: Base.url_decode64!(s, padding: false)

  defp key(alg \\ "ES256") do
    jose =
      case alg do
        "ES256" -> JOSE.JWK.generate_key({:ec, "P-256"})
        "EdDSA" -> JOSE.JWK.generate_key({:okp, :Ed25519})
        _ -> JOSE.JWK.generate_key({:rsa, 2048})
      end

    {_, priv} = JOSE.JWK.to_map(jose)
    {_, pub} = jose |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

    sign =
      case alg do
        "ES256" ->
          fn input ->
            der = :crypto.sign(:ecdsa, :sha256, input, [unb64(priv["d"]), :secp256r1])
            {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
            <<r::unsigned-big-256, s::unsigned-big-256>>
          end

        "EdDSA" ->
          fn input -> :crypto.sign(:eddsa, :none, input, [unb64(priv["d"]), :ed25519]) end

        "RS256" ->
          fn input -> :crypto.sign(:rsa, :sha256, input, rsa_priv(priv)) end

        "PS256" ->
          fn input ->
            :crypto.sign(:rsa, :sha256, input, rsa_priv(priv),
              rsa_padding: :rsa_pkcs1_pss_padding,
              rsa_pss_saltlen: 32
            )
          end
      end

    pub = Map.take(pub, ~w(kty crv x y n e))
    %{alg: alg, jwk: pub, jkt: DPoP.jwk_thumbprint(pub), sign: sign}
  end

  defp rsa_priv(priv), do: Enum.map(~w(e n d), &:binary.decode_unsigned(unb64(priv[&1])))

  defp proof(k, token, claims \\ %{}, opts \\ []) do
    body =
      %{
        "htm" => "POST",
        "htu" => @api,
        "jti" => "j#{System.unique_integer([:positive])}",
        "iat" => System.system_time(:second),
        "ath" => DPoP.access_token_hash(token)
      }
      |> Map.merge(claims)
      |> Enum.reject(fn {_, v} -> v == nil end)
      |> Map.new()

    header = Keyword.get(opts, :header, %{"typ" => "dpop+jwt", "alg" => k.alg, "jwk" => k.jwk})
    input = b64(Jason.encode!(header)) <> "." <> b64(Jason.encode!(body))
    sig = k.sign.(input)

    input =
      if opts[:tamper],
        do: b64(Jason.encode!(header)) <> "." <> b64(~s({"htm":"POST","jti":"x"})),
        else: input

    input <> "." <> b64(sig)
  end

  defp token(jkt \\ nil) do
    now = System.system_time(:second)

    claims = %{
      "iss" => TokenHelper.issuer(),
      "sub" => "user_1",
      "aud" => @api,
      "exp" => now + 300,
      "token_use" => "access_token",
      "scope" => "tools:read",
      "client_id" => "cli_1",
      "jti" => "t#{System.unique_integer([:positive])}"
    }

    claims = if jkt, do: Map.put(claims, "cnf", %{"jkt" => jkt}), else: claims
    TokenHelper.sign(claims)
  end

  defp opts(keys, extra \\ []) do
    TokenHelper.verify_opts(
      Keyword.merge(
        [fetcher: fn _ -> {:ok, keys} end, audience: @api, resource_metadata_url: @meta],
        extra
      )
    )
  end

  defp check(o, scheme, tok, proof, method \\ "POST", url \\ @api <> "?x=1") do
    AccessToken.verify(
      scheme <> " " <> tok,
      Keyword.merge(o, method: method, url: url, dpop: proof)
    )
  end

  defp refused(result, error, name) do
    assert {:error, %{status: 401, error: ^error, www_authenticate: www}} = result, name

    assert String.starts_with?(www, "DPoP "), name
    assert www =~ ~s(error="#{error}"), name
    assert www =~ ~s(algs="ES256), name
  end

  test "accepts a bound token with a matching proof for every algorithm", %{keys: keys} do
    o = opts(keys)

    for alg <- ~w(ES256 RS256 PS256 EdDSA) do
      k = key(alg)
      tok = token(k.jkt)

      assert {:ok, %{dpop_bound: true, subject: "user_1"}} = check(o, "DPoP", tok, proof(k, tok)),
             alg
    end

    assert {:ok, %{dpop_bound: false}} = check(o, "Bearer", token(), nil)
  end

  test "never accepts a bound token as a plain Bearer token", %{keys: keys} do
    o = opts(keys)
    k = key()
    tok = token(k.jkt)
    refused(check(o, "Bearer", tok, proof(k, tok)), "invalid_token", "bearer")
    refused(AccessToken.verify("DPoP " <> tok, o), "invalid_dpop_proof", "no proof")
    unbound = token()
    refused(check(o, "DPoP", unbound, proof(k, unbound)), "invalid_token", "unbound as DPoP")
  end

  test "rejects every bad proof, and a replay", %{keys: keys} do
    o = opts(keys)
    k = key()
    other = key()
    tok = token(k.jkt)
    now = System.system_time(:second)

    hdr = fn typ, alg, jwk ->
      [header: Map.reject(%{"typ" => typ, "alg" => alg, "jwk" => jwk}, fn {_, v} -> v == nil end)]
    end

    cases = [
      {"missing proof", nil},
      {"malformed", "not-a-jwt"},
      {"garbage header", "e30.e30.e30"},
      {"another key", proof(other, tok)},
      {"wrong htm", proof(k, tok, %{"htm" => "GET"})},
      {"wrong htu", proof(k, tok, %{"htu" => "https://api.example.com/other"})},
      {"wrong host", proof(k, tok, %{"htu" => "https://evil.example.com/mcp"})},
      {"relative htu", proof(k, tok, %{"htu" => "/mcp"})},
      {"wrong ath", proof(k, tok, %{"ath" => "nope"})},
      {"no ath", proof(k, tok, %{"ath" => nil})},
      {"proof for another token", proof(k, token(k.jkt))},
      {"stale", proof(k, tok, %{"iat" => now - 3600})},
      {"future", proof(k, tok, %{"iat" => now + 60})},
      {"no iat", proof(k, tok, %{"iat" => nil})},
      {"expired exp", proof(k, tok, %{"exp" => now - 60})},
      {"no jti", proof(k, tok, %{"jti" => nil})},
      {"typ JWT", proof(k, tok, %{}, hdr.("JWT", "ES256", k.jwk))},
      {"alg HS256", proof(k, tok, %{}, hdr.("dpop+jwt", "HS256", k.jwk))},
      {"alg none", proof(k, tok, %{}, hdr.("dpop+jwt", "none", k.jwk))},
      {"no jwk", proof(k, tok, %{}, hdr.("dpop+jwt", "ES256", nil))},
      {"private jwk", proof(k, tok, %{}, hdr.("dpop+jwt", "ES256", Map.put(k.jwk, "d", "AAAA")))},
      {"alg/key mismatch", proof(key("RS256"), tok, %{}, hdr.("dpop+jwt", "RS256", k.jwk))},
      {"bad signature", proof(k, tok, %{}, tamper: true)}
    ]

    for {name, p} <- cases, do: refused(check(o, "DPoP", tok, p), "invalid_dpop_proof", name)

    once = proof(k, tok, %{"jti" => "fixed-#{System.unique_integer([:positive])}"})
    assert {:ok, _} = check(o, "DPoP", tok, once)
    refused(check(o, "DPoP", tok, once), "invalid_dpop_proof", "replay")
    tok_other = token(other.jkt)
    [_, p64, _] = String.split(once, ".")
    jti = Jason.decode!(unb64(p64))["jti"]

    assert {:ok, _} = check(o, "DPoP", tok_other, proof(other, tok_other, %{"jti" => jti})),
           "same jti, other key"
  end

  test "a custom replay store function is used", %{keys: keys} do
    me = self()
    store = fn key, exp -> send(me, {:claimed, key, exp}) && true end
    o = opts(keys, dpop_replay_store: store)
    k = key()
    tok = token(k.jkt)
    assert {:ok, _} = check(o, "DPoP", tok, proof(k, tok, %{"jti" => "custom"}))
    jkt = k.jkt
    assert_received {:claimed, key, _}
    assert key == jkt <> ":custom"
  end

  test "require_dpop refuses an unbound token", %{keys: keys} do
    o = opts(keys, require_dpop: true)
    refused(check(o, "Bearer", token(), nil), "invalid_token", "require_dpop")

    assert {:error, %{status: 401, error: nil, www_authenticate: www}} =
             AccessToken.verify(nil, o)

    assert www =~ ~r/^DPoP .*algs="/
  end

  test "htu normalisation and public_origin", %{keys: keys} do
    o = opts(keys)
    k = key()
    tok = token(k.jkt)

    for htu <- ["HTTPS://API.Example.COM:443/mcp", "https://api.example.com/mcp?other=2#frag"] do
      assert {:ok, _} = check(o, "DPoP", tok, proof(k, tok, %{"htu" => htu})), htu
    end

    refused(
      check(o, "DPoP", tok, proof(k, tok), "POST", "/mcp?x=1"),
      "invalid_dpop_proof",
      "path, no origin"
    )

    assert {:ok, _} =
             check(
               opts(keys, public_origin: "https://api.example.com"),
               "DPoP",
               tok,
               proof(k, tok),
               "post",
               "/mcp?x=1"
             )

    for {given, want} <- [
          {"https://A.example.com:443", "https://a.example.com/"},
          {"http://a.example.com:80/x?y#z", "http://a.example.com/x"},
          {"https://a.example.com:8443/p/", "https://a.example.com:8443/p/"},
          {"https://[::1]:443/p", "https://[::1]/p"}
        ] do
      assert DPoP.normalize_htu(given) == want, given
    end

    assert DPoP.normalize_htu("ftp://x/y") == nil
  end

  test "server nonces", %{keys: keys} do
    clock = :counters.new(1, [])
    :counters.put(clock, 1, System.system_time(:millisecond))

    nonces =
      HmacNonce.new(String.duplicate("s", 32),
        window_seconds: 60,
        now_ms: fn -> :counters.get(clock, 1) end
      )

    o = opts(keys, dpop_nonces: nonces)
    k = key()
    tok = token(k.jkt)
    r = check(o, "DPoP", tok, proof(k, tok))
    refused(r, "use_dpop_nonce", "no nonce")
    {:error, %{dpop_nonce: nonce}} = r
    assert nonce == HmacNonce.current(nonces)

    refused(
      check(o, "DPoP", tok, proof(k, tok, %{"nonce" => "made-up"})),
      "use_dpop_nonce",
      "wrong nonce"
    )

    assert {:ok, %{dpop_nonce: n}} = check(o, "DPoP", tok, proof(k, tok, %{"nonce" => nonce}))
    assert is_binary(n)
    issued = HmacNonce.current(nonces)
    :counters.add(clock, 1, 60_000)
    assert HmacNonce.valid?(nonces, issued)
    :counters.add(clock, 1, 60_000)
    refute HmacNonce.valid?(nonces, issued)

    refused(
      check(o, "DPoP", tok, proof(k, tok, %{"nonce" => issued})),
      "use_dpop_nonce",
      "stale nonce"
    )

    assert_raise ArgumentError, fn -> HmacNonce.new("short") end
  end

  test "helpers" do
    n =
      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

    assert DPoP.jwk_thumbprint(%{
             "kty" => "RSA",
             "e" => "AQAB",
             "alg" => "RS256",
             "kid" => "2011-04-29",
             "n" => n
           }) ==
             "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    assert DPoP.jwk_thumbprint(%{"kty" => "oct", "k" => "x"}) == nil
    key = "helper-#{System.unique_integer([:positive])}"
    assert MemoryReplayStore.claim(key, 1_060_000, 1_000_000)
    refute MemoryReplayStore.claim(key, 1_060_000, 1_000_000)
    assert MemoryReplayStore.claim(key, 1_180_000, 1_120_000)

    doc =
      AccessToken.protected_resource_metadata(@api, "https://auth.example.com", [],
        dpop_bound_access_tokens_required: true
      )

    assert doc["dpop_bound_access_tokens_required"] == true
    assert doc["dpop_signing_alg_values_supported"] == DPoP.algs()

    assert AccessToken.build_www_authenticate(
             scheme: "DPoP",
             error: "use_dpop_nonce",
             description: "n"
           ) ==
             ~s(DPoP error="use_dpop_nonce", error_description="n", algs="#{Enum.join(DPoP.algs(), " ")}")
  end

  test "the RequireAccessToken plug checks DPoP proofs and sets dpop-nonce", %{keys: keys} do
    o =
      AtlasAuth.Plug.RequireAccessToken.init(
        opts(keys, dpop_nonces: HmacNonce.new(String.duplicate("k", 32)))
      )

    k = key("EdDSA")
    tok = token(k.jkt)

    p = fn nonce, jti ->
      proof(k, tok, %{
        "htm" => "PUT",
        "htu" => "https://api.example.com/docs/1",
        "nonce" => nonce,
        "jti" => jti
      })
    end

    send_req = fn proofs ->
      c =
        conn(:put, "https://api.example.com/docs/1?draft=1")
        |> put_req_header("authorization", "DPoP " <> tok)

      c =
        Enum.reduce(proofs, c, fn pr, acc ->
          %{acc | req_headers: acc.req_headers ++ [{"dpop", pr}]}
        end)

      AtlasAuth.Plug.RequireAccessToken.call(c, o)
    end

    uniq = System.unique_integer([:positive])
    first = send_req.([p.(nil, "a#{uniq}")])
    assert first.halted and first.status == 401
    assert [nonce] = get_resp_header(first, "dpop-nonce")
    assert [challenge] = get_resp_header(first, "www-authenticate")
    assert String.starts_with?(challenge, ~s(DPoP error="use_dpop_nonce"))
    ok = send_req.([p.(nonce, "b#{uniq}")])
    refute ok.halted
    assert ok.assigns.atlas_access_token.dpop_bound
    assert [_] = get_resp_header(ok, "dpop-nonce")
    replay = send_req.([p.(nonce, "b#{uniq}")])
    assert replay.halted and replay.status == 401
    assert [c2] = get_resp_header(replay, "www-authenticate")
    assert c2 =~ ~s(error="invalid_dpop_proof")
    two = send_req.([p.(nonce, "c#{uniq}"), p.(nonce, "d#{uniq}")])
    assert two.halted and two.status == 401
  end
end
