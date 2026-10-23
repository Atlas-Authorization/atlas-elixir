defmodule AtlasAuth.Constants do
  @moduledoc "Names the Atlas API accepts in configuration and sends in webhooks."

  @doc """
  Captcha providers (`auth_config.captcha.provider`). Captcha is
  bring-your-own-keys: store the secret first. `vercel_botid` is secret-only:
  set `attestationUrl` instead of a site key.
  """
  def captcha_providers,
    do:
      ~w(none atlas hcaptcha turnstile recaptcha recaptcha_v3 recaptcha_enterprise funcaptcha friendly
           yandex geetest mcaptcha capy seon awswaf perimeterx akamai kasada incapsula captchafox vercel_botid)

  @doc "`auth_config.accountLinkingTrust` values."
  def linking_trust_levels, do: ~w(always verified never)

  @doc "Billing providers an instance can sell end-user plans through (bring your own key)."
  def billing_providers, do: ~w(stripe polar dodo creem chargebee autumn commet)

  @doc "Where the token-signing key can live."
  def signing_key_providers, do: ~w(local aws_kms gcp_kms azure_key_vault)

  @doc "Webhook event types Atlas emits for session custom data and dormant-account reactivation."
  def webhook_session_updated, do: "session.updated"
  def webhook_user_reactivated, do: "user.reactivated"

  @doc "Webhook event types for policy acceptance: a user accepted a version; a version was published."
  def webhook_user_policy_accepted, do: "user.policy_accepted"
  def webhook_policy_version_published, do: "policy.version_published"

  @doc "The security notice sent when a dormant account signs in again."
  def email_template_account_reactivated, do: "account_reactivated"
end
