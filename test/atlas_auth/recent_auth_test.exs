defmodule AtlasAuth.RecentAuthTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{Claims, RecentAuth}

  test "authenticated_within?/3 reads auth_time" do
    now = 1_900_000_000_000
    assert RecentAuth.authenticated_within?(%{"auth_time" => 1_899_999_900}, 300, now)
    refute RecentAuth.authenticated_within?(%{"auth_time" => 1_899_999_000}, 300, now)
    refute RecentAuth.authenticated_within?(%{}, 300, now)
    assert RecentAuth.authenticated_within?(Claims.from_map(%{"auth_time" => 1_899_999_900}), 300, now)
  end

  test "used_multi_factor?/1 reads acr and amr" do
    assert RecentAuth.used_multi_factor?(%{"acr" => "urn:atlas:acr:mfa"})
    assert RecentAuth.used_multi_factor?(%{"amr" => ["pwd", "mfa"]})
    refute RecentAuth.used_multi_factor?(%{"acr" => "urn:atlas:acr:basic", "amr" => ["pwd"]})
  end

  test "mfa_satisfied?/1 prefers the server's verdict, then mfa, acr/amr and SSO" do
    refute RecentAuth.mfa_satisfied?(%{"mfa_satisfied" => false, "mfa" => true})
    assert RecentAuth.mfa_satisfied?(%{"mfa_satisfied" => true})
    assert RecentAuth.mfa_satisfied?(%{"mfa" => true})
    assert RecentAuth.mfa_satisfied?(%{"amr" => ["mfa"]})
    assert RecentAuth.mfa_satisfied?(%{"sso_connection_id" => "sso_1"})
    refute RecentAuth.mfa_satisfied?(%{})
  end

  test "mfa_org_satisfied?/2 matches the active organization" do
    assert RecentAuth.mfa_org_satisfied?(%{})
    refute RecentAuth.mfa_org_satisfied?(%{"org_mfa_required" => true})
    assert RecentAuth.mfa_org_satisfied?(%{"org_mfa_required" => true, "org_mfa_ok" => true})
    assert RecentAuth.mfa_org_satisfied?(%{"org_id" => "org_1"}, "org_1")
    refute RecentAuth.mfa_org_satisfied?(%{"org_id" => "org_2"}, "org_1")
    assert RecentAuth.mfa_org_satisfied?(%{"org_external_id" => "ext", "org_mfa_required" => true, "org_mfa_ok" => true, "org_id" => "org_1"}, "ext")
  end
end
