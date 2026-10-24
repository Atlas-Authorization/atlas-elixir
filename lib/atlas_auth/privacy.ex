defmodule AtlasAuth.Privacy do
  @moduledoc """
  The data-rights (DSAR) executor protocol, receiver side.

  When an instance connects a privacy orchestrator, Atlas opens a case with it
  when an account deletion is scheduled. With `sign_requests` on, those calls
  carry `atlas-id`, `atlas-timestamp` and `atlas-signature` exactly like a
  webhook (HMAC-SHA256 over `id.timestamp.body` with the signing secret), and
  the `privacy_request.*` events sent to a completion endpoint are ordinary
  signed webhooks. `verify_call/4` checks either. Verify the RAW body.

      case AtlasAuth.Privacy.verify_call(raw_body, conn.req_headers, secret) do
        {:ok, %{delivery_id: id, traceparent: tp, event: event}} -> ...
        {:error, _} -> send_resp(conn, 400, "")
      end

  The routes an orchestrator calls (`/v1/privacy/*`) are Backend API
  resources; this verifier-only SDK has no Backend API client.
  """

  alias AtlasAuth.{Trace, Webhook}

  @types ~w(access deletion closure restriction rectification)
  @statuses ~w(pending scheduled processing completed completed_with_retention rejected no_match cancelled)

  @doc "Canonical privacy request types (`erase` is accepted on create and means `deletion`)."
  def types, do: @types

  @doc "Privacy request statuses."
  def statuses, do: @statuses

  @doc "Scope that lets a key call `/v1/privacy/*`."
  def scope_execute, do: "privacy:execute"
  @doc "Scope that lets an erasure also revoke the Sign in with Atlas grant."
  def scope_grants_revoke, do: "privacy:grants:revoke"

  @type call :: %{
          delivery_id: String.t(),
          timestamp: integer(),
          traceparent: String.t() | nil,
          body: binary(),
          event: map() | nil
        }

  @doc """
  Verify a call Atlas makes to a data-rights receiver. Options are those of
  `AtlasAuth.Webhook.verify/4` (`:now_ms`, `:tolerance_ms`). `:delivery_id` is
  also the `Idempotency-Key` Atlas sends: deduplicate retries on it. `:event`
  is set when the body is a webhook envelope (`privacy_request.*`).
  """
  @spec verify_call(binary(), [{String.t(), String.t()}] | map(), String.t(), keyword()) ::
          {:ok, call()} | {:error, Webhook.reason()}
  def verify_call(body, headers, secret, opts \\ []) do
    with {:ok, v} <- Webhook.verify(body, headers, secret, opts) do
      event = if is_map(v.event) and is_binary(v.event["type"]) and v.event["type"] != "", do: v.event

      {:ok,
       %{
         delivery_id: v.delivery_id,
         timestamp: v.timestamp,
         traceparent: Trace.from_headers(headers),
         body: body,
         event: event
       }}
    end
  end

  @doc """
  The privacy request carried by a `privacy_request.updated` /
  `privacy_request.completed` event (its `data`), or `nil`.
  """
  @spec request_from_event(map() | nil) :: map() | nil
  def request_from_event(%{"data" => %{} = data}), do: data
  def request_from_event(_), do: nil
end
