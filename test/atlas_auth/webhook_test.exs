defmodule AtlasAuth.WebhookTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.Webhook

  @secret "whsec_test_secret"
  @now 1_757_937_600_000
  @body ~s({"id":"evt_1","type":"user.updated","data":{"id":"user_1"}})

  defp sign(id, ts, body, secret \\ @secret) do
    mac = :crypto.mac(:hmac, :sha256, secret, "#{id}.#{ts}.#{body}") |> Base.encode64()
    [{"atlas-id", id}, {"atlas-timestamp", Integer.to_string(ts)}, {"atlas-signature", "v1," <> mac}]
  end

  test "returns the delivery id and timestamp" do
    assert {:ok, %{delivery_id: "evt_1", timestamp: ts, event: event}} =
             Webhook.verify(@body, sign("evt_1", @now - 1000, @body), @secret, now_ms: @now)

    assert ts == @now - 1000
    assert event["type"] == "user.updated"
  end

  test "accepts a map with any header casing" do
    headers = Map.new(sign("evt_1", @now, @body), fn {k, v} -> {String.upcase(k), v} end)
    assert {:ok, _} = Webhook.verify(@body, headers, @secret, now_ms: @now)
  end

  test "rejections" do
    headers = sign("evt_1", @now, @body)
    tampered = String.replace(@body, "user_1", "user_2")
    assert {:error, :signature_mismatch} = Webhook.verify(tampered, headers, @secret, now_ms: @now)
    assert {:error, :signature_mismatch} =
             Webhook.verify(@body, sign("evt_1", @now, @body, "whsec_x"), @secret, now_ms: @now)

    assert {:error, :stale_timestamp} =
             Webhook.verify(@body, sign("evt_1", @now - 360_000, @body), @secret, now_ms: @now)

    assert {:error, :stale_timestamp} =
             Webhook.verify(@body, sign("evt_1", @now + 360_000, @body), @secret, now_ms: @now)

    assert {:error, :missing_headers} = Webhook.verify(@body, [], @secret, now_ms: @now)
    bad = List.keyreplace(headers, "atlas-signature", 0, {"atlas-signature", "v2,abc"})
    assert {:error, :malformed_signature} = Webhook.verify(@body, bad, @secret, now_ms: @now)
  end
end
