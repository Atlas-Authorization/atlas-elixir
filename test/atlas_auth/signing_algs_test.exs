defmodule AtlasAuth.SigningAlgsTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{BackchannelLogout, OIDC, Verifier}

  @issuer "https://inst-alg.atlas.example"
  @client "client_alg"

  # One runtime key per algorithm: {alg, generator, expected kty}.
  @algs [
    {"RS256", {:rsa, 2048}, "RSA"},
    {"PS256", {:rsa, 2048}, "RSA"},
    {"ES256", {:ec, :secp256r1}, "EC"},
    {"ES384", {:ec, :secp384r1}, "EC"},
    {"EdDSA", {:okp, :Ed25519}, "OKP"}
  ]

  defp public_jwks(jwk, alg, kid) do
    {_, map} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    [Map.merge(map, %{"kid" => kid, "alg" => alg, "use" => "sig"})]
  end

  defp sign(jwk, alg, kid, claims, header \\ %{}) do
    now = System.system_time(:second)
    payload = Map.merge(%{"iss" => @issuer, "sub" => "user_1", "iat" => now, "nbf" => now, "exp" => now + 300}, claims)
    {_, compact} = jwk |> JOSE.JWT.sign(Map.merge(%{"alg" => alg, "kid" => kid}, header), payload) |> JOSE.JWS.compact()
    compact
  end

  defp opts(keys), do: [issuer: @issuer, jwks_url: @issuer <> "/jwks/#{System.unique_integer([:positive])}", fetcher: fn _ -> {:ok, keys} end, cache: start_cache()]

  defp start_cache do
    name = :"cache_#{System.unique_integer([:positive])}"
    {:ok, _} = AtlasAuth.JWKSCache.start_link(name: name)
    name
  end

  for {alg, gen, kty} <- @algs do
    describe "#{alg}" do
      test "a session token, an ID token and a logout token verify" do
        jwk = JOSE.JWK.generate_key(unquote(Macro.escape(gen)))
        keys = public_jwks(jwk, unquote(alg), "k1")
        assert hd(keys)["kty"] == unquote(kty)
        o = opts(keys)

        assert {:ok, %AtlasAuth.Claims{sub: "user_1"}} = Verifier.verify(sign(jwk, unquote(alg), "k1", %{}), o)

        id = sign(jwk, unquote(alg), "k1", %{"aud" => @client, "nonce" => "n1"})
        assert {:ok, %{"sub" => "user_1"}} = OIDC.verify_id_token(id, o ++ [client_id: @client, nonce: "n1"])
        assert {:error, %OIDC.Error{code: :invalid_token}} = OIDC.verify_id_token(id, o ++ [client_id: @client, nonce: "other"])

        lt =
          sign(jwk, unquote(alg), "k1", %{
            "aud" => @client,
            "jti" => "j1",
            "sid" => "s1",
            "events" => %{"http://schemas.openid.net/event/backchannel-logout" => %{}}
          }, %{"typ" => "logout+jwt"})

        assert {:ok, %{sid: "s1"}} = BackchannelLogout.verify(lt, o ++ [client_id: @client])
      end

      test "a token signed by another key of the same type is refused" do
        jwk = JOSE.JWK.generate_key(unquote(Macro.escape(gen)))
        other = JOSE.JWK.generate_key(unquote(Macro.escape(gen)))
        assert {:error, :invalid} = Verifier.verify(sign(other, unquote(alg), "k1", %{}), opts(public_jwks(jwk, unquote(alg), "k1")))
      end

      test "a key that declares another alg is not used" do
        jwk = JOSE.JWK.generate_key(unquote(Macro.escape(gen)))
        keys = public_jwks(jwk, "HS256", "k1")
        assert {:error, :invalid} = Verifier.verify(sign(jwk, unquote(alg), "k1", %{}), opts(keys))
      end
    end
  end

  describe "no algorithm confusion" do
    test "an RSA key never verifies an ES256 or EdDSA header, nor an EC key an RS256 one" do
      rsa = JOSE.JWK.generate_key({:rsa, 2048})
      ec = JOSE.JWK.generate_key({:ec, :secp256r1})
      ec384 = JOSE.JWK.generate_key({:ec, :secp384r1})
      ed = JOSE.JWK.generate_key({:okp, :Ed25519})

      # The attacker signs with the matching private-key type but names the key's JWKS entry under another alg.
      assert {:error, :invalid} = Verifier.verify(sign(ec, "ES256", "k1", %{}), opts(public_jwks(rsa, "RS256", "k1") |> Enum.map(&Map.delete(&1, "alg"))))
      assert {:error, :invalid} = Verifier.verify(sign(ed, "EdDSA", "k1", %{}), opts(public_jwks(rsa, "RS256", "k1") |> Enum.map(&Map.delete(&1, "alg"))))
      assert {:error, :invalid} = Verifier.verify(sign(rsa, "RS256", "k1", %{}), opts(public_jwks(ec, "ES256", "k1") |> Enum.map(&Map.delete(&1, "alg"))))
      # P-384 key under ES256 and P-256 key under ES384 do not match.
      assert {:error, :invalid} = Verifier.verify(sign(ec384, "ES384", "k1", %{}), opts(public_jwks(ec, "ES256", "k1") |> Enum.map(&Map.delete(&1, "alg"))))
      assert {:error, :invalid} = Verifier.verify(sign(ec, "ES256", "k1", %{}), opts(public_jwks(ec384, "ES384", "k1") |> Enum.map(&Map.delete(&1, "alg"))))
    end

    test "none and HS* are refused, including an HMAC token keyed with the RSA public key" do
      rsa = JOSE.JWK.generate_key({:rsa, 2048})
      keys = public_jwks(rsa, "RS256", "k1")
      o = opts(keys)
      now = System.system_time(:second)
      b64 = &Base.url_encode64(&1, padding: false)
      payload = Jason.encode!(%{"iss" => @issuer, "sub" => "u", "exp" => now + 60, "iat" => now})

      none = b64.(Jason.encode!(%{"alg" => "none", "kid" => "k1"})) <> "." <> b64.(payload) <> "."
      assert {:error, _} = Verifier.verify(none, o)

      {_, pem} = rsa |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()

      for hs <- ["HS256", "HS384", "HS512"] do
        hmac = JOSE.JWK.from_oct(pem) |> JOSE.JWT.sign(%{"alg" => hs, "kid" => "k1"}, Jason.decode!(payload)) |> JOSE.JWS.compact() |> elem(1)
        assert {:error, _} = Verifier.verify(hmac, o)
      end
    end
  end
end
