defmodule AtlasAuth.Trace do
  @moduledoc """
  W3C `traceparent` helpers.

  Atlas stores the trace id of a `traceparent` header on webhook deliveries,
  back-channel deliveries, referral calls and the executor requests it triggers,
  and sends one on the calls it makes to your receivers. (`X-...-Trace` style
  headers are not used; `traceparent` only.)
  """

  @pattern ~r/^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/

  @doc "Mint a fresh sampled traceparent (`00-<32 hex>-<16 hex>-01`)."
  @spec new() :: String.t()
  def new do
    trace = random_hex(16)
    span = random_hex(8)
    "00-#{trace}-#{span}-01"
  end

  defp random_hex(bytes) do
    hex = :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)
    if String.match?(hex, ~r/\A0+\z/), do: String.slice(hex, 0..-2//1) <> "1", else: hex
  end

  @doc """
  Parse a traceparent into `{:ok, %{trace_id:, span_id:, flags:}}`, or `:error`
  when malformed (including all-zero ids).
  """
  @spec parse(term()) :: {:ok, %{trace_id: String.t(), span_id: String.t(), flags: String.t()}} | :error
  def parse(value) when is_binary(value) do
    case Regex.run(@pattern, value |> String.trim() |> String.downcase()) do
      [_, trace, span, flags] ->
        if trace == String.duplicate("0", 32) or span == String.duplicate("0", 16),
          do: :error,
          else: {:ok, %{trace_id: trace, span_id: span, flags: flags}}

      _ ->
        :error
    end
  end

  def parse(_), do: :error

  @doc """
  The traceparent Atlas sent, read from request headers (a list of `{name,
  value}` pairs or a map; names matched case-insensitively), or `nil` when
  absent or malformed.
  """
  @spec from_headers([{String.t(), String.t()}] | map()) :: String.t() | nil
  def from_headers(headers) when is_map(headers), do: from_headers(Map.to_list(headers))

  def from_headers(headers) when is_list(headers) do
    value =
      Enum.find_value(headers, fn {k, v} ->
        if String.downcase(to_string(k)) == "traceparent", do: String.trim(to_string(v))
      end)

    if value && match?({:ok, _}, parse(value)), do: value
  end
end
