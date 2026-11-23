defmodule AtlasAuth.ApiKeyAssertion do
  @moduledoc """
  Signs the short-lived assertion a key-pair API key presents instead of a secret: ES256 for P-256
  keys (raw `r || s`), EdDSA for Ed25519 keys.

  Send the result as `token` to `Atlas.ApiKeys.post_verify/3` or as `assertion` to
  `Atlas.ApiKeys.post_token/3`.
  """

  @doc """
  Signs an assertion with the PKCS#8 PEM private key Atlas returned once at create.

  Options: `:ttl_seconds` (default 300), `:scope` (space-separated, narrows the key's own scopes),
  `:jti` (default random).
  """
  @spec sign(String.t(), String.t(), String.t(), keyword()) :: String.t()
  def sign(private_key_pem, key_id, audience, opts \\ []) do
    jwk = JOSE.JWK.from_pem(private_key_pem)

    alg =
      case JOSE.JWK.to_map(jwk) do
        {_, %{"kty" => "EC", "crv" => "P-256"}} -> "ES256"
        {_, %{"kty" => "OKP", "crv" => "Ed25519"}} -> "EdDSA"
        _ -> raise ArgumentError, "the key must be a P-256 or Ed25519 private key"
      end

    now = System.os_time(:second)

    claims =
      %{
        "iss" => key_id,
        "aud" => audience,
        "iat" => now,
        "exp" => now + Keyword.get(opts, :ttl_seconds, 300),
        "jti" => Keyword.get_lazy(opts, :jti, fn -> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false) end)
      }
      |> then(fn c -> if opts[:scope], do: Map.put(c, "scope", opts[:scope]), else: c end)

    # JOSE signs ES256 as the raw 64-byte r || s a JWS carries.
    {_, compact} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => alg, "kid" => key_id, "typ" => "JWT"}, claims)
      |> JOSE.JWS.compact()

    compact
  end
end
