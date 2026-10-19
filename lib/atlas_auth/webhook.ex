defmodule AtlasAuth.Webhook do
  @moduledoc """
  Verify an inbound Atlas webhook, for the customer consuming events.

  Atlas signs every delivery: `atlas-signature: v1,<base64>` is HMAC-SHA256
  over `"<id>.<timestamp>.<raw body>"` keyed with the endpoint secret
  (`whsec_...`), sent with `atlas-id` and `atlas-timestamp` (epoch ms). A
  delivery more than five minutes from now, in either direction, is refused.
  Verify the RAW body, before any JSON decode. Matches `verifyWebhook` in
  `@atlasauth/backend`.

      case AtlasAuth.Webhook.verify(raw_body, conn.req_headers, secret) do
        {:ok, %{delivery_id: id, event: event}} ->
          # `id` is the same on every retry of one event: skip it if already handled.
          handle(event)

        {:error, _reason} ->
          send_resp(conn, 400, "")
      end
  """

  @replay_tolerance_ms 5 * 60_000

  @typedoc "A verified delivery. `delivery_id` is the signed `atlas-id`; `timestamp` the signed `atlas-timestamp` (epoch ms)."
  @type verified :: %{event: map() | nil, delivery_id: String.t(), timestamp: integer()}

  @type reason :: :missing_headers | :malformed_signature | :stale_timestamp | :signature_mismatch

  @doc """
  Verify a delivery. `headers` is a list of `{name, value}` pairs (as in
  `conn.req_headers`) or a map; names are matched case-insensitively.

  Options: `:now_ms` (override the clock), `:tolerance_ms` (default 300_000).
  """
  @spec verify(binary(), [{String.t(), String.t()}] | map(), String.t(), keyword()) ::
          {:ok, verified()} | {:error, reason()}
  def verify(body, headers, secret, opts \\ []) when is_binary(body) and is_binary(secret) do
    now = Keyword.get_lazy(opts, :now_ms, fn -> System.system_time(:millisecond) end)
    tolerance = Keyword.get(opts, :tolerance_ms, @replay_tolerance_ms)

    with {:ok, id, ts_raw, signature} <- read_headers(headers),
         {:ok, provided} <- parse_signature(signature),
         {:ok, timestamp} <- parse_timestamp(ts_raw, now, tolerance),
         :ok <- check_mac(secret, id, timestamp, body, provided) do
      event =
        case Jason.decode(body) do
          {:ok, map} when is_map(map) -> map
          _ -> nil
        end

      {:ok, %{event: event, delivery_id: id, timestamp: timestamp}}
    end
  end

  defp read_headers(headers) do
    id = header(headers, "atlas-id")
    ts = header(headers, "atlas-timestamp")
    sig = header(headers, "atlas-signature")

    if blank?(id) or blank?(ts) or blank?(sig),
      do: {:error, :missing_headers},
      else: {:ok, id, ts, sig}
  end

  defp parse_signature(signature) do
    case String.split(signature, ",", parts: 2) do
      ["v1", provided] when provided != "" -> {:ok, provided}
      _ -> {:error, :malformed_signature}
    end
  end

  defp parse_timestamp(raw, now, tolerance) do
    case Integer.parse(String.trim(raw)) do
      {ts, ""} when abs(now - ts) <= tolerance -> {:ok, ts}
      _ -> {:error, :stale_timestamp}
    end
  end

  defp check_mac(secret, id, timestamp, body, provided) do
    expected =
      :crypto.mac(:hmac, :sha256, secret, [id, ".", Integer.to_string(timestamp), ".", body])
      |> Base.encode64()

    if byte_size(expected) == byte_size(provided) and :crypto.hash_equals(expected, provided),
      do: :ok,
      else: {:error, :signature_mismatch}
  end

  defp header(headers, name) when is_map(headers), do: header(Map.to_list(headers), name)

  defp header(headers, name) when is_list(headers) do
    Enum.find_value(headers, fn {k, v} ->
      if String.downcase(to_string(k)) == name, do: to_string(v)
    end)
  end

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(_), do: false
end
