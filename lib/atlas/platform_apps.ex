defmodule Atlas.PlatformApps do
  @moduledoc """
  Platform API operations under `/v1/platform/apps` (outside the generated Backend
  API modules). Build the client with a platform key: `Atlas.new("psk_...")`.
  Same calling convention as the `Atlas.<Resource>` modules.
  """

  @doc ~S"""
  Show a newly created app's secret keys once more: for a script that crashed between
  the create response (`initial_secret_reveal` gives the path and deadline) and saving
  the secret. Works once, within 10 minutes of the create, for the platform that created
  the app. Returns `%{"object" => "initial_secret", "app_id", "instance_id", "key_id",
  "secret", "sibling_instance" => %{...}}`; a key rotated or revoked since is `nil`. A
  second call (or one after the window) is 410: rotate instead. With
  `params: [dry_run: true]` nothing is consumed and the response carries `available` and
  `expires_at`. A create retried with the same Idempotency-Key never re-shows a secret
  (`secret: nil`, `secret_redacted: true`).

  `POST /v1/platform/apps/{id}/initial_secret/reveal`. Required scope: `platform:secrets:write`.
  """
  def reveal_initial_secret(client, id, opts \\ []),
    do: Atlas.Client.request(client, :post, "/v1/platform/apps/{id}/initial_secret/reveal", %{"id" => id}, nil, opts)
end
