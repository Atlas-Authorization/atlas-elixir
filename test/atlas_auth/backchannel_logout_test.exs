defmodule AtlasAuth.BackchannelLogoutTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{BackchannelLogout, TokenHelper}

  @event "http://schemas.openid.net/event/backchannel-logout"

  setup do
    {:ok, opts: TokenHelper.verify_opts(client_id: TokenHelper.client_id())}
  end

  defp url64(bin), do: Base.url_encode64(bin, padding: false)

  test "a valid logout token verifies and returns sub, sid, jti, iat", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"jti" => "jti_1", "iat" => 1_700_000_000, "exp" => :delete})
    opts = Keyword.put(opts, :now_ms, 1_700_000_010_000)

    assert {:ok, claims} = BackchannelLogout.verify(token, opts)
    assert claims == %{sub: "user_2abc", sid: "sess_2def", jti: "jti_1", iat: 1_700_000_000}
  end

  test "the top-level delegate verifies too", %{opts: opts} do
    assert {:ok, %{sid: "sess_2def"}} =
             AtlasAuth.verify_logout_token(TokenHelper.sign_logout(), opts)
  end

  test "aud may be a list containing the client id", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"aud" => ["other", TokenHelper.client_id()]})
    assert {:ok, _} = BackchannelLogout.verify(token, opts)
  end

  test "sid alone or sub alone is enough", %{opts: opts} do
    assert {:ok, %{sub: nil, sid: "sess_2def"}} =
             BackchannelLogout.verify(TokenHelper.sign_logout(%{"sub" => :delete}), opts)

    assert {:ok, %{sub: "user_2abc", sid: nil}} =
             BackchannelLogout.verify(TokenHelper.sign_logout(%{"sid" => :delete}), opts)
  end

  test "typ is compared case-insensitively", %{opts: opts} do
    token = TokenHelper.sign_logout(%{}, header: %{"typ" => "Logout+JWT"})
    assert {:ok, _} = BackchannelLogout.verify(token, opts)
  end

  test "a wrong typ is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{}, header: %{"typ" => "JWT"})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a token carrying a nonce is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"nonce" => "n-1"})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "missing events is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"events" => :delete})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "events without the back-channel member is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"events" => %{"urn:other" => %{}}})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "an events value that is not an object is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"events" => %{@event => "yes"}})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a wrong audience is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"aud" => "someone_else"})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)

    no_aud = TokenHelper.sign_logout(%{"aud" => :delete})
    assert {:error, :invalid} = BackchannelLogout.verify(no_aud, opts)
  end

  test "a wrong issuer is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"iss" => "https://evil.example"})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "an expired token is rejected", %{opts: opts} do
    now = System.system_time(:second)
    token = TokenHelper.sign_logout(%{"iat" => now - 600, "exp" => now - 300})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "iat far in the future is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"iat" => System.system_time(:second) + 3600})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a missing iat is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"iat" => :delete})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a missing jti is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"jti" => :delete})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a token with neither sid nor sub is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"sid" => :delete, "sub" => :delete})
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a token signed by a different key is rejected", %{opts: opts} do
    other = JOSE.JWK.generate_key({:rsa, 2048})
    token = TokenHelper.sign_logout(%{}, jwk: other)
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a tampered signature is rejected", %{opts: opts} do
    token = TokenHelper.sign_logout() |> TokenHelper.tamper_signature()
    assert {:error, :invalid} = BackchannelLogout.verify(token, opts)
  end

  test "a non-RS256 token is rejected", %{opts: opts} do
    header =
      %{"alg" => "HS256", "kid" => TokenHelper.kid(), "typ" => "logout+jwt"}
      |> Jason.encode!()
      |> url64()

    payload =
      %{
        "iss" => TokenHelper.issuer(),
        "aud" => TokenHelper.client_id(),
        "sid" => "s",
        "jti" => "j",
        "iat" => System.system_time(:second),
        "events" => %{@event => %{}}
      }
      |> Jason.encode!()
      |> url64()

    signing_input = header <> "." <> payload
    sig = :crypto.mac(:hmac, :sha256, "secret", signing_input) |> url64()

    assert {:error, :invalid} = BackchannelLogout.verify(signing_input <> "." <> sig, opts)
  end

  test "a malformed token is :malformed", %{opts: opts} do
    assert {:error, :malformed} = BackchannelLogout.verify("nope", opts)
    assert {:error, :malformed} = BackchannelLogout.verify("", opts)
    assert {:error, :malformed} = BackchannelLogout.verify(nil, opts)
  end

  test "client_id is required", %{opts: opts} do
    assert_raise ArgumentError, fn ->
      BackchannelLogout.verify(TokenHelper.sign_logout(), Keyword.delete(opts, :client_id))
    end
  end
end
