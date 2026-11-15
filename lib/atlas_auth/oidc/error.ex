defmodule AtlasAuth.OIDC.Error do
  @moduledoc """
  A relying-party failure. `code` is one of `:state_mismatch`, `:issuer_mismatch`,
  `:invalid_request`, `:invalid_token`, `:token_exchange_failed`, `:access_denied`
  (also the OAuth `error` the authorization server redirected back with: see
  `oauth_error`), `:discovery_failed`, `:reauthentication_required` and
  `:subject_mismatch`. `clear_cookie` is a `Set-Cookie` value that removes the flow
  cookie: send it with your error response too.
  """
  defexception [:code, :message, :oauth_error, :description, :status, :clear_cookie]

  @type t :: %__MODULE__{}
end
