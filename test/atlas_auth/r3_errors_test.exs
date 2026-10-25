defmodule AtlasAuth.R3ErrorsTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.Errors

  test "managed_waf_not_configured code and meta.action" do
    assert Errors.managed_waf_not_configured() == "MANAGED_WAF_NOT_CONFIGURED"

    err =
      Errors.parse(%{
        "errors" => [
          %{"code" => "MANAGED_WAF_NOT_CONFIGURED", "message" => "m", "meta" => %{"action" => "provision"}}
        ]
      })

    assert err.code == Errors.managed_waf_not_configured()
    assert err.action == "provision"
    assert Errors.parse(%{"code" => "NOT_FOUND"}).action == nil
  end

  test "provisioned account and domain error codes" do
    assert Errors.test_account_restricted() == "TEST_ACCOUNT_RESTRICTED"
    assert Errors.provisioned_account_limit_reached() == "PROVISIONED_ACCOUNT_LIMIT_REACHED"
    assert Errors.domain_not_verified() == "DOMAIN_NOT_VERIFIED"

    err = Errors.parse(%{"errors" => [%{"code" => "DOMAIN_NOT_VERIFIED", "message" => "m"}]})
    assert err.code == Errors.domain_not_verified()
  end
end
