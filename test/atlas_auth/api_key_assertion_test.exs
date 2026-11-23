defmodule AtlasAuth.ApiKeyAssertionTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.ApiKeyAssertion

  defp pem(jwk), do: jwk |> JOSE.JWK.to_pem() |> elem(1)

  test "ES256 assertion is raw r||s and verifies with the public key" do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    token = ApiKeyAssertion.sign(pem(jwk), "key_1", "ins_1", scope: "read", jti: "j1")

    assert %{"alg" => "ES256", "kid" => "key_1", "typ" => "JWT"} = JOSE.JWS.peek_protected(token) |> Jason.decode!()
    assert {true, %JOSE.JWT{fields: claims}, _} = JOSE.JWT.verify_strict(JOSE.JWK.to_public(jwk), ["ES256"], token)
    assert %{"iss" => "key_1", "aud" => "ins_1", "scope" => "read", "jti" => "j1"} = claims
    assert claims["exp"] - claims["iat"] == 300
    [_, _, sig] = String.split(token, ".")
    assert byte_size(Base.url_decode64!(sig, padding: false)) == 64
  end

  test "EdDSA assertion verifies with the public key" do
    jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
    token = ApiKeyAssertion.sign(pem(jwk), "key_2", "ins_1", ttl_seconds: 60)

    assert %{"alg" => "EdDSA"} = JOSE.JWS.peek_protected(token) |> Jason.decode!()
    assert {true, %JOSE.JWT{fields: claims}, _} = JOSE.JWT.verify_strict(JOSE.JWK.to_public(jwk), ["EdDSA"], token)
    assert claims["exp"] - claims["iat"] == 60
    assert claims["jti"] != ""
  end
end
