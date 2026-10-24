defmodule AtlasAuth.WebhookEvents do
  @moduledoc """
  Webhook event names: the canonical spellings, the deprecated aliases Atlas
  still delivers, and the events added with endpoint health, secret keys,
  status incidents and the data-rights executor.

  An endpoint that lists a deprecated spelling by name still receives it (with
  the same `atlas-id` as the canonical event) until the sunset date. Match on
  `canonical/1` so your handler works for either spelling.
  """

  # alias => {canonical, kind}. A `:rename` is sent whenever the canonical event
  # is; a `:companion` only for some occurrences.
  @aliases %{
    "session.ended" => {"session.revoked", :companion},
    "session.removed" => {"session.revoked", :companion},
    "organizationMembership.created" => {"organization_membership.created", :rename},
    "organizationMembership.updated" => {"organization_membership.updated", :rename},
    "organizationMembership.deleted" => {"organization_membership.deleted", :rename},
    "organization.membership.deleted" => {"organization_membership.deleted", :rename},
    "organizationInvitation.created" => {"organization_invitation.created", :rename},
    "organizationInvitation.accepted" => {"organization_invitation.accepted", :rename},
    "organizationInvitation.revoked" => {"organization_invitation.revoked", :rename},
    "organizationInvitation.declined" => {"organization_invitation.declined", :rename},
    "organizationInvitation.resent" => {"organization_invitation.resent", :rename},
    "teamMembership.created" => {"team_membership.created", :rename},
    "teamMembership.deleted" => {"team_membership.deleted", :rename},
    "appRole.created" => {"app_role.created", :rename},
    "appRole.updated" => {"app_role.updated", :rename},
    "appRole.deleted" => {"app_role.deleted", :rename},
    "organizationDomain.created" => {"organization_domain.created", :rename},
    "organizationDomain.updated" => {"organization_domain.updated", :rename},
    "organizationDomain.deleted" => {"organization_domain.deleted", :rename},
    "organization.settings.updated" => {"organization_settings.updated", :rename},
    "waitlistEntry.created" => {"waitlist_entry.created", :rename},
    "waitlistEntry.updated" => {"waitlist_entry.updated", :rename},
    "billing.subscription.created" => {"billing_subscription.created", :rename},
    "billing.subscription.updated" => {"billing_subscription.updated", :rename},
    "billing.subscription.canceled" => {"billing_subscription.canceled", :rename},
    "billing.invoice.payment_failed" => {"billing_invoice.payment_failed", :rename},
    "billing.trial.started" => {"billing_trial.started", :rename},
    "billing.trial.will_end" => {"billing_trial.will_end", :rename},
    "billing.trial.ended" => {"billing_trial.ended", :rename},
    "entitlement.override.created" => {"entitlement_override.created", :rename},
    "entitlement.override.deleted" => {"entitlement_override.deleted", :rename},
    "entitlement.override.expired" => {"entitlement_override.expired", :rename},
    "scimToken.created" => {"scim_token.created", :rename},
    "scimToken.revoked" => {"scim_token.revoked", :rename},
    "ssoConnection.created" => {"sso_connection.created", :rename},
    "ssoConnection.updated" => {"sso_connection.updated", :rename},
    "ssoConnection.deleted" => {"sso_connection.deleted", :rename},
    "user.data_export.requested" => {"user.data_export_requested", :rename},
    "user.deletion_cancelled" => {"user.deletion_canceled", :companion}
  }

  @doc "Every deprecated spelling mapped to `{canonical, :rename | :companion}`."
  @spec aliases() :: %{String.t() => {String.t(), :rename | :companion}}
  def aliases, do: @aliases

  @doc "True when `name` is a deprecated spelling."
  @spec deprecated?(String.t()) :: boolean()
  def deprecated?(name), do: Map.has_key?(@aliases, name)

  @doc "The canonical name for any spelling; an unknown name is returned unchanged."
  @spec canonical(String.t()) :: String.t()
  def canonical(name) do
    case Map.fetch(@aliases, name) do
      {:ok, {canonical, _kind}} -> canonical
      :error -> name
    end
  end

  @doc "Every name an event is known by: the canonical one first, then its aliases (sorted)."
  @spec spellings(String.t()) :: [String.t()]
  def spellings(name) do
    canonical = canonical(name)

    aliases =
      for {alias_name, {^canonical, _}} <- @aliases, do: alias_name

    [canonical | Enum.sort(aliases)]
  end

  # Endpoint health, delivery targets, test event.
  def webhook_endpoint_failing, do: "webhook_endpoint.failing"
  def webhook_endpoint_disabled, do: "webhook_endpoint.disabled"
  def webhook_endpoint_recovered, do: "webhook_endpoint.recovered"
  def delivery_target_failing, do: "delivery_target.failing"
  def delivery_target_disabled, do: "delivery_target.disabled"
  def delivery_target_recovered, do: "delivery_target.recovered"
  def webhook_test, do: "webhook.test"

  # Secret keys (audience `security`). `secret_key.expiring` data carries
  # `days_left` and `threshold_days`.
  def secret_key_expiring, do: "secret_key.expiring"
  def secret_key_revoked, do: "secret_key.revoked"

  # Status incidents.
  def status_incident_created, do: "status.incident.created"
  def status_incident_updated, do: "status.incident.updated"
  def status_incident_resolved, do: "status.incident.resolved"

  # Data-rights executor; the user deletion events also reach Sign in with Atlas app webhooks.
  def privacy_request_updated, do: "privacy_request.updated"
  def privacy_request_completed, do: "privacy_request.completed"
  def user_deletion_scheduled, do: "user.deletion_scheduled"
  def user_deletion_canceled, do: "user.deletion_canceled"
end
