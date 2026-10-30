defmodule AtlasAuth.Webhook do
  @moduledoc """
  Verify an inbound Atlas webhook, for the customer consuming events.

  Atlas signs every delivery: `atlas-signature: v1,<base64>` is HMAC-SHA256
  over `"<id>.<timestamp>.<raw body>"` keyed with the endpoint secret
  (`whsec_...`), sent with `atlas-id` and `atlas-timestamp` (epoch ms). A
  delivery more than five minutes from now, in either direction, is refused.
  The header may carry several space-separated `v1,<base64>` entries (one per
  secret while a secret rotates with an overlap); the delivery verifies when
  any one matches. Verify the RAW body, before any JSON decode. Matches `verifyWebhook` in
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

  @doc """
  Verify a delivery that may carry a v2 signature.

  An endpoint whose `signature_versions` include `v2` signs HMAC-SHA256 over
  `"<id>.<timestamp>.<url>.<body>"`, where `url` is the exact URL Atlas POSTed
  to (your endpoint's `url`), so a captured delivery cannot be replayed to
  another URL. A delivery verifies when any `v1` entry (over
  `id.timestamp.body`) or any `v2` entry matches; entries of unknown versions
  are ignored. With `require_v2: true` only a `v2` entry is accepted.

  Options: those of `verify/4` plus `:require_v2` (default `false`).
  """
  @spec verify_url(binary(), [{String.t(), String.t()}] | map(), String.t(), String.t(), keyword()) ::
          {:ok, verified()} | {:error, reason()}
  def verify_url(body, headers, secret, endpoint_url, opts \\ [])
      when is_binary(body) and is_binary(secret) and is_binary(endpoint_url) do
    now = Keyword.get_lazy(opts, :now_ms, fn -> System.system_time(:millisecond) end)
    tolerance = Keyword.get(opts, :tolerance_ms, @replay_tolerance_ms)
    require_v2 = Keyword.get(opts, :require_v2, false)

    with {:ok, id, ts_raw, signature} <- read_headers(headers),
         v1 = if(require_v2, do: [], else: signatures_of(signature, "v1")),
         v2 = signatures_of(signature, "v2"),
         :ok <- if(v1 == [] and v2 == [], do: {:error, :malformed_signature}, else: :ok),
         {:ok, timestamp} <- parse_timestamp(ts_raw, now, tolerance),
         :ok <- check_v1_v2(secret, id, timestamp, endpoint_url, body, v1, v2) do
      {:ok, %{event: decode_event(body), delivery_id: id, timestamp: timestamp}}
    end
  end

  @doc """
  Verify a Standard Webhooks delivery: an application webhook (an event your
  app published with `POST /v1/app_events`) as your customer receives it.

  Headers `webhook-id`, `webhook-timestamp` (epoch seconds) and
  `webhook-signature` (space-separated `v1,<base64>` entries; any one may
  match, so a rotating secret verifies). The signature is HMAC-SHA256 over
  `"<id>.<timestamp>.<raw body>"` keyed with the base64-decoded part of the
  secret after `whsec_`. Matches `verifyStandardWebhook` in `@atlasauth/backend`.

  Options: `:now_ms` (override the clock), `:tolerance_ms` (default 300_000).
  The returned `timestamp` is the signed `webhook-timestamp` in seconds.
  """
  @spec verify_standard(binary(), [{String.t(), String.t()}] | map(), String.t(), keyword()) ::
          {:ok, verified()} | {:error, reason()}
  def verify_standard(body, headers, secret, opts \\ []) when is_binary(body) and is_binary(secret) do
    now_s = div(Keyword.get_lazy(opts, :now_ms, fn -> System.system_time(:millisecond) end), 1000)
    tolerance_s = div(Keyword.get(opts, :tolerance_ms, @replay_tolerance_ms), 1000)

    with {:ok, id, ts_raw, signature} <-
           read_headers(headers, "webhook-id", "webhook-timestamp", "webhook-signature"),
         {:ok, provided} <- parse_signature(signature),
         {:ok, timestamp} <- parse_seconds(ts_raw, now_s, tolerance_s),
         :ok <- check_standard_mac(secret, id, timestamp, body, provided) do
      {:ok, %{event: decode_event(body), delivery_id: id, timestamp: timestamp}}
    end
  end

  defp parse_seconds(raw, now_s, tolerance_s) do
    with true <- Regex.match?(~r/\A\d+\z/, raw),
         ts = String.to_integer(raw),
         true <- abs(now_s - ts) <= tolerance_s do
      {:ok, ts}
    else
      _ -> {:error, :stale_timestamp}
    end
  end

  defp check_standard_mac(secret, id, timestamp, body, provided) do
    encoded = String.replace_prefix(secret, "whsec_", "")

    # A key that is not base64 can never have produced a valid signature.
    decoded =
      with :error <- Base.decode64(encoded), do: Base.decode64(encoded, padding: false)

    case decoded do
      {:ok, key} ->
        expected = :crypto.mac(:hmac, :sha256, key, [id, ".", Integer.to_string(timestamp), ".", body]) |> Base.encode64()
        if Enum.reduce(provided, false, fn c, acc -> same?(expected, c) or acc end),
          do: :ok,
          else: {:error, :signature_mismatch}

      :error ->
        {:error, :signature_mismatch}
    end
  end

  defp check_v1_v2(secret, id, timestamp, url, body, v1, v2) do
    ts = Integer.to_string(timestamp)
    e1 = mac(secret, [id, ".", ts, ".", body])
    e2 = mac(secret, [id, ".", ts, ".", url, ".", body])

    matched =
      Enum.reduce(v1, false, fn c, acc -> same?(e1, c) or acc end) or
        Enum.reduce(v2, false, fn c, acc -> same?(e2, c) or acc end)

    if matched, do: :ok, else: {:error, :signature_mismatch}
  end

  defp decode_event(body) do
    case Jason.decode(body) do
      {:ok, map} when is_map(map) -> map
      _ -> nil
    end
  end

  defp mac(secret, data), do: :crypto.mac(:hmac, :sha256, secret, data) |> Base.encode64()

  defp same?(expected, candidate),
    do: byte_size(expected) == byte_size(candidate) and :crypto.hash_equals(expected, candidate)

  # The `<base64>` values of every entry of one version in an
  # `atlas-signature` header (`v1,<b64> v2,<b64>`).
  defp signatures_of(signature, version) do
    signature
    |> String.split()
    |> Enum.flat_map(fn entry ->
      case String.split(entry, ",", parts: 2) do
        [^version, value] when value != "" -> [value]
        _ -> []
      end
    end)
  end

  defp read_headers(headers, id_name \\ "atlas-id", ts_name \\ "atlas-timestamp", sig_name \\ "atlas-signature") do
    id = header(headers, id_name)
    ts = header(headers, ts_name)
    sig = header(headers, sig_name)

    if blank?(id) or blank?(ts) or blank?(sig),
      do: {:error, :missing_headers},
      else: {:ok, id, ts, sig}
  end

  # One `v1,<base64>` entry, or several separated by spaces (while an endpoint
  # secret rotates, Atlas signs with the old and the new secret). Entries of
  # another version are skipped.
  defp parse_signature(signature) do
    provided =
      signature
      |> String.split()
      |> Enum.flat_map(fn entry ->
        case String.split(entry, ",", parts: 2) do
          ["v1", value] when value != "" -> [value]
          _ -> []
        end
      end)

    if provided == [], do: {:error, :malformed_signature}, else: {:ok, provided}
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

    # Compare every entry (no early exit), each in constant time.
    matched =
      Enum.reduce(provided, false, fn candidate, acc ->
        same = byte_size(expected) == byte_size(candidate) and :crypto.hash_equals(expected, candidate)
        acc or same
      end)

    if matched, do: :ok, else: {:error, :signature_mismatch}
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
