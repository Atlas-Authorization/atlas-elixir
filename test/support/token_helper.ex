defmodule AtlasAuth.TokenHelper do
  @moduledoc """
  Test support: mint real RS256 tokens and build a matching JWKS, all in-memory,
  so the verifier tests exercise genuine signatures with no network.

  An RSA keypair is generated once; `jwks/0` returns the public half as a JWKS key
  list suitable for injecting as the verifier's `:fetcher`, and `sign/2` mints a
  token with that key and a chosen claim set.
  """

  @kid "test-key-1"
  @issuer "https://inst-test.atlas.example"

  def issuer, do: @issuer
  def kid, do: @kid

  @doc "A freshly generated RSA private JWK, cached for the VM's lifetime."
  def private_jwk do
    case :persistent_term.get({__MODULE__, :jwk}, nil) do
      nil ->
        jwk = JOSE.JWK.generate_key({:rsa, 2048})
        :persistent_term.put({__MODULE__, :jwk}, jwk)
        jwk

      jwk ->
        jwk
    end
  end

  @doc "The JWKS public key list (what the JWKS endpoint would serve)."
  def jwks do
    {_mods, map} =
      private_jwk()
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()

    [Map.merge(map, %{"kid" => @kid, "alg" => "RS256", "use" => "sig"})]
  end

  @doc "A fetcher closure returning the JWKS — inject as the verifier's `:fetcher`."
  def fetcher, do: fn _url -> {:ok, jwks()} end

  @doc """
  Mint a signed token. `claims` overrides the defaults; `kid` overrides the
  header kid (default #{@kid}).
  """
  def sign(claims \\ %{}, opts \\ []) do
    now = System.system_time(:second)

    default = %{
      "iss" => @issuer,
      "sub" => "user_2abc",
      "sid" => "sess_2def",
      "iat" => now,
      "nbf" => now,
      "exp" => now + 3600,
      "org_id" => "org_2ghi",
      "org_role" => "admin",
      "org_permissions" => ["billing:read", "members:read"]
    }

    payload = Map.merge(default, claims)
    header = %{"alg" => "RS256", "kid" => Keyword.get(opts, :kid, @kid)}

    {_mods, compact} =
      private_jwk()
      |> JOSE.JWT.sign(header, payload)
      |> JOSE.JWS.compact()

    compact
  end

  @doc "Default verifier options wired to the in-memory fetcher (no network)."
  def verify_opts(extra \\ []) do
    unique = System.unique_integer([:positive])

    Keyword.merge(
      [
        jwks_url: "https://inst-test.atlas.example/jwks/#{unique}",
        issuer: @issuer,
        fetcher: fetcher()
      ],
      extra
    )
  end

  @doc "Flip one character of a compact JWT's signature to corrupt it."
  def tamper_signature(token) do
    [h, p, sig] = String.split(token, ".")
    <<first::utf8, rest::binary>> = sig
    swapped = if first == ?A, do: ?B, else: ?A
    h <> "." <> p <> "." <> <<swapped::utf8>> <> rest
  end
end
