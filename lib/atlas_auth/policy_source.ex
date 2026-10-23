defmodule AtlasAuth.PolicySource do
  @moduledoc """
  Atlas policy source protocol v1: the helpers for the system that SERVES an
  instance's policy documents (a CMS, a docs platform, your own service).

  Atlas to you: `GET {endpoint_url}/policies` (the full feed) or
  `GET {endpoint_url}/policies?key=<key>` (one policy, after your event), signed
  with the source's signing secret: `atlas-id`, `atlas-timestamp` (epoch
  milliseconds) and `atlas-signature: v1,<base64 HMAC-SHA256>` over
  `"{atlas-id}.{atlas-timestamp}.GET\\n{path+query}"`. Verify it with
  `verify_feed_request/1`, then answer
  `{"object":"policy_list","policies":[...]}` (at most 512 KB per version).

  You to Atlas: `POST {webhook_url}` (from `GET /v1/instance/policy_source`), an
  event signed with the same secret: `sign_published/3`, `sign_retired/2` or
  `sign_event/2` (Atlas-style headers), or any Standard Webhooks library. Atlas
  then re-fetches that policy; it never stores content from the event.

      def feed(conn, _params) do
        result =
          AtlasAuth.PolicySource.verify_feed_request(
            method: conn.method,
            path_and_query: conn.request_path <> if(conn.query_string == "", do: "", else: "?" <> conn.query_string),
            headers: conn.req_headers,
            secret: secret
          )

        case result do
          {:ok, %{key: key}} -> json(conn, build_feed(key))
          {:error, _reason} -> send_resp(conn, 401, "")
        end
      end
  """

  @protocol_version "2026-10-24"
  @version_header "atlas-policies-version"
  @tolerance_ms 5 * 60_000

  @type reason ::
          :missing_headers
          | :malformed_signature
          | :stale_timestamp
          | :signature_mismatch
          | :wrong_method

  @type verified :: %{
          delivery_id: String.t(),
          timestamp: integer(),
          key: String.t() | nil,
          protocol_version: String.t() | nil
        }

  @doc "The protocol version Atlas sends in `atlas-policies-version`."
  def protocol_version, do: @protocol_version

  @doc "The header carrying the protocol version."
  def version_header, do: @version_header

  @doc """
  Verify Atlas's signed GET of your feed. Options:

    * `:method` - the request method (anything but `GET` is `{:error, :wrong_method}`); omit to skip the check
    * `:path_and_query` - the path AND query exactly as received (required)
    * `:headers` - `[{name, value}]` pairs or a map; names match case-insensitively (required)
    * `:secret` - the source's signing secret (required)
    * `:now_ms` - override the clock; `:tolerance_ms` - default 300_000

  Several space-separated `v1,<base64>` values are accepted (any one matching passes);
  other versions are ignored. On success `:key` is the `key` query parameter (`nil`
  for the full feed).
  """
  @spec verify_feed_request(keyword()) :: {:ok, verified()} | {:error, reason()}
  def verify_feed_request(opts) do
    path_and_query = Keyword.fetch!(opts, :path_and_query)
    headers = Keyword.fetch!(opts, :headers)
    secret = Keyword.fetch!(opts, :secret)
    now = Keyword.get_lazy(opts, :now_ms, fn -> System.system_time(:millisecond) end)
    tolerance = Keyword.get(opts, :tolerance_ms, @tolerance_ms)

    with :ok <- check_method(Keyword.get(opts, :method)),
         {:ok, id, ts_raw, signature} <- read_headers(headers),
         {:ok, provided} <- parse_signature(signature),
         {:ok, timestamp} <- parse_timestamp(ts_raw, now, tolerance),
         :ok <- check_mac(secret, id, ts_raw, "GET\n" <> path_and_query, provided) do
      {:ok,
       %{
         delivery_id: id,
         timestamp: timestamp,
         key: query_param(path_and_query, "key"),
         protocol_version: header(headers, @version_header)
       }}
    end
  end

  @doc """
  Sign a `policy.published` event for `POST {webhook_url}`. Returns
  `%{body: binary, headers: [{name, value}]}`: send `body` byte-for-byte with `headers`.
  Options: `:id` (default `evt_<random>`), `:timestamp_ms` (default now).
  """
  @spec sign_published(String.t(), String.t(), String.t(), keyword()) :: %{
          body: binary(),
          headers: [{String.t(), String.t()}]
        }
  def sign_published(key, version, secret, opts \\ []),
    do:
      sign_event(%{type: "policy.published", key: key, version: version}, [
        {:secret, secret} | opts
      ])

  @doc "Sign a `policy.retired` event (its history is kept). See `sign_published/4`."
  @spec sign_retired(String.t(), String.t(), keyword()) :: %{
          body: binary(),
          headers: [{String.t(), String.t()}]
        }
  def sign_retired(key, secret, opts \\ []),
    do: sign_event(%{type: "policy.retired", key: key}, [{:secret, secret} | opts])

  @doc """
  Sign an event map (`%{type: "policy.published", key: .., version: ..}` or
  `%{type: "policy.retired", key: ..}`); `:secret` is required in `opts`.
  """
  @spec sign_event(map(), keyword()) :: %{body: binary(), headers: [{String.t(), String.t()}]}
  def sign_event(%{type: type, key: key} = event, opts)
      when type in ["policy.published", "policy.retired"] do
    if type == "policy.published" and not (is_binary(event[:version]) and event[:version] != "") do
      raise ArgumentError, "a policy.published event needs a version"
    end

    fields =
      [
        {"occurred_at",
         DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()},
        {"type", type},
        {"key", key}
      ] ++
        if(type == "policy.published", do: [{"version", event.version}], else: [])

    # Built by hand so the keys keep their order on the wire.
    body =
      "{" <>
        Enum.map_join(fields, ",", fn {k, v} -> Jason.encode!(k) <> ":" <> Jason.encode!(v) end) <>
        "}"

    sign_body(body, opts)
  end

  @doc "Sign an already serialised JSON body (`:secret` required; `:id`, `:timestamp_ms` optional)."
  @spec sign_body(binary(), keyword()) :: %{body: binary(), headers: [{String.t(), String.t()}]}
  def sign_body(body, opts) when is_binary(body) do
    secret = Keyword.fetch!(opts, :secret)

    id =
      Keyword.get_lazy(opts, :id, fn ->
        "evt_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
      end)

    ts =
      opts
      |> Keyword.get_lazy(:timestamp_ms, fn -> System.system_time(:millisecond) end)
      |> Integer.to_string()

    %{
      body: body,
      headers: [
        {"atlas-id", id},
        {"atlas-timestamp", ts},
        {"atlas-signature", "v1," <> mac(secret, id, ts, body)}
      ]
    }
  end

  defp check_method(nil), do: :ok

  defp check_method(method) do
    if String.upcase(to_string(method)) == "GET", do: :ok, else: {:error, :wrong_method}
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

  defp check_mac(secret, id, ts_raw, payload, provided) do
    expected = mac(secret, id, ts_raw, payload)

    # Compare every entry (no early exit), each in constant time.
    matched =
      Enum.reduce(provided, false, fn candidate, acc ->
        same =
          byte_size(expected) == byte_size(candidate) and :crypto.hash_equals(expected, candidate)

        acc or same
      end)

    if matched, do: :ok, else: {:error, :signature_mismatch}
  end

  defp mac(secret, id, ts, payload),
    do: :crypto.mac(:hmac, :sha256, secret, [id, ".", ts, ".", payload]) |> Base.encode64()

  defp query_param(path_and_query, name) do
    case String.split(path_and_query, "?", parts: 2) do
      [_, query] ->
        query
        |> URI.query_decoder()
        |> Enum.find_value(fn {k, v} -> if k == name, do: v end)

      _ ->
        nil
    end
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
