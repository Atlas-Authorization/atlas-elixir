defmodule AtlasAuth.Errors do
  @moduledoc """
  Atlas API error codes and helpers to read an error response body (the JSON
  you get back from the Backend API if you call it yourself).

  `INSUFFICIENT_SCOPE` is the current code for a key that lacks a scope; the
  former `SCOPE_MISSING` is still tolerated everywhere (`insufficient_scope?/1`).
  """

  def insufficient_scope, do: "INSUFFICIENT_SCOPE"
  @doc "The former spelling of `insufficient_scope/0`; still sent by older deployments."
  def scope_missing, do: "SCOPE_MISSING"
  def step_up_required, do: "STEP_UP_REQUIRED"
  def route_not_found, do: "ROUTE_NOT_FOUND"
  def not_a_live_instance, do: "NOT_A_LIVE_INSTANCE"
  def test_mode_only, do: "TEST_MODE_ONLY"
  def testing_unavailable, do: "TESTING_UNAVAILABLE"
  def partner_link_unavailable, do: "PARTNER_LINK_UNAVAILABLE"
  def origin_not_allowed, do: "ORIGIN_NOT_ALLOWED"
  @doc "422: managed WAF provision or deprovision on an instance with no WAF configuration saved (`meta.action`, see `parse/1`)."
  def managed_waf_not_configured, do: "MANAGED_WAF_NOT_CONFIGURED"
  @doc "403: a Sign in with Atlas test or review account used outside the app it was made for."
  def test_account_restricted, do: "TEST_ACCOUNT_RESTRICTED"
  @doc "409: the account already holds its maximum number of test and review accounts (`meta.limit`)."
  def provisioned_account_limit_reached, do: "PROVISIONED_ACCOUNT_LIMIT_REACHED"
  @doc "422: the setting or address needs a domain the account has verified, and this one is not."
  def domain_not_verified, do: "DOMAIN_NOT_VERIFIED"

  @doc """
  Pull the first error item out of a decoded error body (`%{"errors" => [..]}`
  or a bare item map). Returns a map with `:code`, `:message`, and, when
  present, `:required_scope`, `:did_you_mean`, `:allowed_methods`, `:docs_url`, `:action`
  (`meta.action`, set on `MANAGED_WAF_NOT_CONFIGURED`);
  `nil` when the body has no error item.
  """
  @spec parse(term()) :: map() | nil
  def parse(%{"errors" => [item | _]}), do: parse(item)

  def parse(%{"code" => code} = item) when is_binary(code) do
    meta = if is_map(item["meta"]), do: item["meta"], else: %{}

    %{
      code: code,
      message: item["message"],
      required_scope: meta["required_scope"],
      action: meta["action"],
      did_you_mean: list(item["did_you_mean"] || meta["did_you_mean"]),
      allowed_methods: list(item["allowed_methods"] || meta["allowed_methods"]),
      docs_url: item["docs_url"]
    }
  end

  def parse(_), do: nil

  @doc "True for `INSUFFICIENT_SCOPE` and the former `SCOPE_MISSING`."
  @spec insufficient_scope?(term()) :: boolean()
  def insufficient_scope?(code) when is_binary(code), do: code in ["INSUFFICIENT_SCOPE", "SCOPE_MISSING"]
  def insufficient_scope?(%{code: code}), do: insufficient_scope?(code)
  def insufficient_scope?(_), do: false

  defp list(l) when is_list(l), do: Enum.filter(l, &is_binary/1)
  defp list(_), do: []
end
