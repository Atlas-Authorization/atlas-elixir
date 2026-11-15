defmodule AtlasAuth.TxnTokenTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{TokenHelper, TxnToken}

  @domain "payments.example.com"

  defp opts, do: TokenHelper.verify_opts(trust_domain: @domain)

  defp mint(claims \\ %{}, header \\ %{}) do
    now = System.system_time(:second)

    base = %{
      "aud" => @domain,
      "txn" => "txn_1",
      "scope" => "orders:read orders:write",
      "req_wl" => "checkout",
      "events" => :delete,
      "jti" => :delete,
      "iat" => now,
      "exp" => now + 120
    }

    TokenHelper.sign_logout(Map.merge(base, claims), header: Map.merge(%{"typ" => "txntoken+jwt"}, header))
  end

  test "a valid token verifies and its scopes are split" do
    assert {:ok, %{claims: %{"txn" => "txn_1"}, scopes: ["orders:read", "orders:write"]}} = TxnToken.verify(mint(), opts())
  end

  test "refuses a token for another trust domain" do
    assert {:error, :invalid} = TxnToken.verify(mint(%{"aud" => "other.example.com"}), opts())
  end

  test "refuses a wrong typ, a wrong issuer and an expired token" do
    assert {:error, :invalid} = TxnToken.verify(mint(%{}, %{"typ" => "JWT"}), opts())
    assert {:error, :invalid} = TxnToken.verify(mint(%{"iss" => "https://evil.example"}), opts())
    past = System.system_time(:second) - 600
    assert {:error, :invalid} = TxnToken.verify(mint(%{"iat" => past - 60, "exp" => past}), opts())
  end

  test "refuses a token missing a required claim" do
    assert {:error, {:missing_claim, "req_wl"}} = TxnToken.verify(mint(%{"req_wl" => :delete}), opts())
  end

  test "refuses a tampered signature" do
    assert {:error, _} = TxnToken.verify(mint() |> TokenHelper.tamper_signature(), opts())
  end
end
