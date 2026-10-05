defmodule AtlasAuth.VerifierTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{Claims, TokenHelper, Verifier}

  setup do
    # A unique jwks_url per test keeps each test's cache entry isolated.
    {:ok, opts: TokenHelper.verify_opts()}
  end

  test "a valid token verifies and returns typed claims", %{opts: opts} do
    token = TokenHelper.sign()

    assert {:ok, %Claims{} = claims} = Verifier.verify(token, opts)
    assert claims.sub == "user_2abc"
    assert claims.sid == "sess_2def"
    assert claims.org_id == "org_2ghi"
    assert claims.org_role == "admin"
    assert Claims.has_permission?(claims, "billing:read")
    refute Claims.has_permission?(claims, "billing:write")
    assert Claims.has_role?(claims, "admin")
    refute Claims.has_role?(claims, "member")
  end

  test "a token minted by the wrong issuer is rejected", %{opts: opts} do
    token = TokenHelper.sign(%{"iss" => "https://evil.example"})
    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "an expired token is rejected", %{opts: opts} do
    past = System.system_time(:second) - 3600
    token = TokenHelper.sign(%{"iat" => past - 60, "nbf" => past - 60, "exp" => past})
    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "a not-yet-valid (nbf in the future) token is rejected", %{opts: opts} do
    future = System.system_time(:second) + 3600
    token = TokenHelper.sign(%{"nbf" => future})
    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "a tampered signature is rejected", %{opts: opts} do
    token = TokenHelper.sign() |> TokenHelper.tamper_signature()
    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "§13.1: a token carrying token_use: access is rejected", %{opts: opts} do
    token = TokenHelper.sign(%{"token_use" => "access"})
    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "§13.1: a token carrying an aud claim is rejected", %{opts: opts} do
    token = TokenHelper.sign(%{"aud" => "some-rp"})
    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "an absent token_use/aud is a valid session (backward-compat)", %{opts: opts} do
    # Default claims carry neither — the happy path above already covers this,
    # but assert the guard does not over-reject.
    assert {:ok, _} = Verifier.verify(TokenHelper.sign(), opts)
  end

  test "a malformed (non three-part) token is :malformed", %{opts: opts} do
    assert {:error, :malformed} = Verifier.verify("not-a-jwt", opts)
    assert {:error, :malformed} = Verifier.verify("", opts)
    assert {:error, :malformed} = Verifier.verify(nil, opts)
  end

  test "alg confusion: a non-RS256 token is rejected", %{opts: opts} do
    # Hand-build an HS256-headed token signed with an HMAC; RS256 pinning must
    # refuse it before any key is even selected.
    header = %{"alg" => "HS256", "kid" => TokenHelper.kid()} |> Jason.encode!() |> url64()
    payload = %{"iss" => TokenHelper.issuer(), "sub" => "x"} |> Jason.encode!() |> url64()
    signing_input = header <> "." <> payload
    sig = :crypto.mac(:hmac, :sha256, "secret", signing_input) |> url64()
    token = signing_input <> "." <> sig

    assert {:error, :invalid} = Verifier.verify(token, opts)
  end

  test "authorized_parties: azp not in the allowlist is :unauthorized_party", %{opts: _} do
    opts = TokenHelper.verify_opts(authorized_parties: ["https://app.example"])
    token = TokenHelper.sign(%{"azp" => "https://other.example"})
    assert {:error, :unauthorized_party} = Verifier.verify(token, opts)
  end

  test "authorized_parties: an allowed azp passes" do
    opts = TokenHelper.verify_opts(authorized_parties: ["https://app.example"])
    token = TokenHelper.sign(%{"azp" => "https://app.example"})
    assert {:ok, %Claims{azp: "https://app.example"}} = Verifier.verify(token, opts)
  end

  test "authenticate_request: Bearer header wins over cookie", %{opts: opts} do
    good = TokenHelper.sign(%{"sub" => "from_header"})
    bad = TokenHelper.sign(%{"iss" => "https://evil.example"})

    headers = [
      {"authorization", "Bearer " <> good},
      {"cookie", "__session=" <> bad}
    ]

    assert {:ok, %Claims{sub: "from_header"}} = Verifier.authenticate_request(headers, opts)
  end

  test "authenticate_request: falls back to the __session cookie", %{opts: opts} do
    token = TokenHelper.sign(%{"sub" => "from_cookie"})
    headers = [{"cookie", "other=1; __session=" <> token <> "; more=2"}]
    assert {:ok, %Claims{sub: "from_cookie"}} = Verifier.authenticate_request(headers, opts)
  end

  test "authenticate_request: no token is :malformed", %{opts: opts} do
    assert {:error, :malformed} = Verifier.authenticate_request([], opts)
  end

  defp url64(bin), do: Base.url_encode64(bin, padding: false)
end
