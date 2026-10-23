defmodule AtlasAuth.LegacyIssuersTest do
  use ExUnit.Case, async: false

  alias AtlasAuth.{Claims, LegacyIssuers, TokenHelper, Verifier}

  @old "https://app.example.com"

  setup_all do
    keys = %{
      "ed-1" => {"EdDSA", JOSE.JWK.generate_key({:okp, :Ed25519})},
      "ec-1" => {"ES256", JOSE.JWK.generate_key({:ec, "P-256"})},
      "ec512" => {"ES512", JOSE.JWK.generate_key({:ec, "P-521"})},
      "rsa-1" => {"RS256", JOSE.JWK.generate_key({:rsa, 2048})}
    }

    jwks =
      Enum.map(keys, fn {kid, {_alg, jwk}} ->
        {_, map} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
        Map.put(map, "kid", kid)
      end)

    {:ok, keys: keys, jwks: jwks}
  end

  setup do
    LegacyIssuers.clear_subjects()
    :ok
  end

  defp sign(keys, kid, claims, alg \\ nil) do
    {default_alg, jwk} = keys[kid]

    {_, token} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => alg || default_alg, "kid" => kid}, claims)
      |> JOSE.JWS.compact()

    token
  end

  defp claims(extra \\ %{}) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => @old,
        "sub" => "ba_user_1",
        "exp" => now + 600,
        "iat" => now,
        "email" => "a@example.com"
      },
      extra
    )
  end

  defp entry(jwks, extra \\ []) do
    Keyword.merge(
      [
        issuer: @old,
        until: System.system_time(:millisecond) + 3_600_000,
        jwks: jwks,
        resolve_subject: fn
          "ba_user_1", _ -> "user_atlas_1"
          _, _ -> nil
        end
      ],
      extra
    )
  end

  defp opts(entries, extra \\ []),
    do: TokenHelper.verify_opts(Keyword.merge([legacy_issuers: entries], extra))

  test "accepts every Better Auth algorithm and maps the subject", %{keys: keys, jwks: jwks} do
    for {kid, alg} <- [
          {"ed-1", "EdDSA"},
          {"ec-1", "ES256"},
          {"ec512", "ES512"},
          {"rsa-1", "RS256"},
          {"rsa-1", "PS256"}
        ] do
      assert {:ok, %Claims{} = c} =
               Verifier.verify(sign(keys, kid, claims(), alg), opts([entry(jwks)])),
             "#{alg}"

      assert c.sub == "user_atlas_1"
      assert c.iss == @old
      assert c.external_id == "ba_user_1"
      assert c.raw["legacy"] == %{"kind" => "better_auth", "issuer" => @old, "sub" => "ba_user_1"}
    end

    assert LegacyIssuers.algorithms() == ["EdDSA", "ES256", "ES512", "RS256", "PS256"]
  end

  test "Atlas tokens still verify and keys never cross", %{keys: keys, jwks: jwks} do
    o = opts([entry(jwks)])
    assert {:ok, %Claims{sub: "user_2abc"}} = Verifier.verify(TokenHelper.sign(), o)
    # An Atlas-issuer token signed with an OLD key is refused.
    forged = sign(keys, "rsa-1", claims(%{"iss" => TokenHelper.issuer()}))
    assert {:error, :invalid} = Verifier.verify(forged, o)
    # An old-issuer token signed with the Atlas key is refused.
    assert {:error, :invalid} =
             Verifier.verify(TokenHelper.sign(%{"iss" => @old, "sub" => "ba_user_1"}), o)
  end

  test "refuses outside the window, without exp, on audience and unmapped subjects", %{
    keys: keys,
    jwks: jwks
  } do
    token = sign(keys, "ed-1", claims())
    ended = entry(jwks, until: 1_000)
    assert {:error, :invalid} = Verifier.verify(token, opts([ended]))

    assert {:error, :invalid} =
             Verifier.verify(token, opts([entry(jwks, until: "2001-01-01T00:00:00Z")]))

    assert {:ok, _} = Verifier.verify(token, opts([entry(jwks, until: ~U[2099-01-01 00:00:00Z])]))

    o = opts([entry(jwks)])

    assert {:error, :invalid} =
             Verifier.verify(sign(keys, "ed-1", Map.delete(claims(), "exp")), o)

    assert {:error, :invalid} = Verifier.verify(sign(keys, "ed-1", claims(%{"exp" => 1})), o)

    assert {:error, :invalid} =
             Verifier.verify(sign(keys, "ed-1", claims(%{"sub" => "ba_other"})), o)

    aud = opts([entry(jwks, audience: "https://api.example.com")])
    assert {:error, :invalid} = Verifier.verify(token, aud)

    assert {:ok, _} =
             Verifier.verify(
               sign(keys, "ed-1", claims(%{"aud" => ["x", "https://api.example.com"]})),
               aud
             )

    id_only = claims() |> Map.delete("sub") |> Map.put("id", "ba_user_1")
    assert {:ok, %Claims{sub: "user_atlas_1"}} = Verifier.verify(sign(keys, "ed-1", id_only), o)
  end

  test "algorithm pinning", %{keys: keys, jwks: jwks} do
    only_ed = opts([entry(jwks, algorithms: ["EdDSA"])])
    assert {:ok, _} = Verifier.verify(sign(keys, "ed-1", claims()), only_ed)
    assert {:error, :invalid} = Verifier.verify(sign(keys, "rsa-1", claims()), only_ed)
    # The header kid selects the key, and the key's type fixes the algorithm.
    {_, ec} = keys["ec-1"]

    {_, mixed} =
      ec |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "rsa-1"}, claims()) |> JOSE.JWS.compact()

    assert {:error, :invalid} = Verifier.verify(mixed, opts([entry(jwks)]))

    none =
      Base.url_encode64(~s({"alg":"none","kid":"ed-1"}), padding: false) <>
        "." <> Base.url_encode64(Jason.encode!(claims()), padding: false) <> "."

    assert {:error, :invalid} = Verifier.verify(none, opts([entry(jwks)]))
  end

  test "configuration errors raise", %{jwks: jwks} do
    token = TokenHelper.sign()

    assert_raise ArgumentError, ~r/cannot be the Atlas issuer/, fn ->
      Verifier.verify(token, opts([entry(jwks, issuer: TokenHelper.issuer())]))
    end

    assert_raise ArgumentError, ~r/until/, fn ->
      Verifier.verify(token, opts([entry(jwks, until: "soon")]))
    end

    assert_raise ArgumentError, ~r/exactly one/, fn ->
      Verifier.verify(
        token,
        opts([entry(jwks, jwks_url: "https://app.example.com/api/auth/jwks")])
      )
    end

    assert_raise ArgumentError, ~r/secret_key/, fn ->
      Verifier.verify(token, opts([Keyword.delete(entry(jwks), :resolve_subject)]))
    end
  end

  test "fetches the old key set by URL through the shared cache", %{keys: keys, jwks: jwks} do
    me = self()

    fetcher = fn url ->
      send(me, {:fetched, url})
      {:ok, jwks}
    end

    url = "https://app.example.com/api/auth/jwks/#{System.unique_integer([:positive])}"
    e = entry(nil, jwks: nil, jwks_url: url)
    o = opts([e], legacy_fetcher: fetcher)

    for _ <- 1..3,
        do:
          assert(
            {:ok, %Claims{sub: "user_atlas_1"}} = Verifier.verify(sign(keys, "ed-1", claims()), o)
          )

    assert_received {:fetched, ^url}
    refute_received {:fetched, _}

    down =
      opts([entry(nil, jwks: nil, jwks_url: url <> "-down")],
        legacy_fetcher: fn _ -> {:error, :down} end
      )

    assert {:error, :no_keys} = Verifier.verify(sign(keys, "ed-1", claims()), down)
  end

  test "azp allowlist applies to legacy tokens", %{keys: keys, jwks: jwks} do
    o = opts([entry(jwks)], authorized_parties: ["https://app.example.com"])

    assert {:error, :unauthorized_party} =
             Verifier.verify(sign(keys, "ed-1", claims(%{"azp" => "https://evil.example"})), o)

    assert {:ok, _} = Verifier.verify(sign(keys, "ed-1", claims()), o)
  end

  test "the default resolver looks up external_id with the secret key and caches", %{
    keys: keys,
    jwks: jwks
  } do
    me = self()

    getter = fn url, headers ->
      send(me, {:get, url, headers})

      if String.contains?(url, "external_id=ba_user_1"),
        do: {:ok, 200, ~s({"object":"list","data":[{"id":"user_atlas_9"}]})},
        else: {:ok, 200, ~s({"object":"list","data":[]})}
    end

    e = Keyword.delete(entry(jwks), :resolve_subject)
    o = opts([e], secret_key: "sk_test_x", api_url: "https://api.atlas.test/", getter: getter)
    token = sign(keys, "ed-1", claims())
    assert {:ok, %Claims{sub: "user_atlas_9"}} = Verifier.verify(token, o)
    assert {:ok, %Claims{sub: "user_atlas_9"}} = Verifier.verify(token, o)
    assert_received {:get, url, headers}
    refute_received {:get, _, _}
    assert url =~ "https://api.atlas.test/v1/users?"
    assert url =~ "limit=1"
    assert {"authorization", "Bearer sk_test_x"} in headers

    assert {:error, :invalid} =
             Verifier.verify(sign(keys, "ed-1", claims(%{"sub" => "ba_nobody"})), o)

    # A failed lookup is not cached.
    LegacyIssuers.clear_subjects()
    failing = opts([e], secret_key: "sk_test_x", getter: fn _, _ -> {:ok, 500, ""} end)
    assert {:error, :invalid} = Verifier.verify(token, failing)
    assert {:ok, %Claims{sub: "user_atlas_9"}} = Verifier.verify(token, o)
  end

  test "until accepts DateTime, ms and ISO-8601" do
    assert LegacyIssuers.until_ms(~U[1970-01-01 00:00:01Z]) == 1000
    assert LegacyIssuers.until_ms(5) == 5
    assert LegacyIssuers.until_ms("2026-12-31T02:00:00+02:00") == 1_798_675_200_000
    assert LegacyIssuers.until_ms("nope") == 0
    assert LegacyIssuers.peek_issuer("a.b") == nil
  end
end
