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

  test "several signatures verify when one matches" do
    headers = sign("evt_1", @now, @body)
    {"atlas-signature", fresh} = List.keyfind(headers, "atlas-signature", 0)
    {"atlas-signature", stale} = List.keyfind(sign("evt_1", @now, @body, "whsec_old_secret"), "atlas-signature", 0)
    with_sig = fn value -> List.keyreplace(headers, "atlas-signature", 0, {"atlas-signature", value}) end

    for value <- ["#{stale} #{fresh}", "#{fresh} #{stale}", "v2,abc #{fresh}"] do
      assert {:ok, _} = Webhook.verify(@body, with_sig.(value), @secret, now_ms: @now)
    end

    assert {:error, :signature_mismatch} =
             Webhook.verify(@body, with_sig.("#{stale} #{stale}"), @secret, now_ms: @now)

    assert {:error, :malformed_signature} =
             Webhook.verify(@body, with_sig.("v2,abc v0,def"), @secret, now_ms: @now)
  end

  @key "0123456789abcdefghijklmnop"
  @std_secret "whsec_" <> Base.encode64(@key)
  @now_s 1_757_937_600

  defp std_sign(key, id, ts, body),
    do: "v1," <> (:crypto.mac(:hmac, :sha256, key, "#{id}.#{ts}.#{body}") |> Base.encode64())

  defp std_headers(sig),
    do: [{"webhook-id", "msg_1"}, {"webhook-timestamp", Integer.to_string(@now_s)}, {"webhook-signature", sig}]

  describe "verify_standard/4" do
    test "verifies and returns the id, timestamp (seconds) and event" do
      headers = std_headers(std_sign(@key, "msg_1", @now_s, @body))

      assert {:ok, %{delivery_id: "msg_1", timestamp: @now_s, event: %{"type" => "user.updated"}}} =
               Webhook.verify_standard(@body, headers, @std_secret, now_ms: @now_s * 1000)
    end

    test "any entry of a rotated signature list verifies" do
      sig = std_sign("old-key", "msg_1", @now_s, @body) <> " " <> std_sign(@key, "msg_1", @now_s, @body)
      assert {:ok, _} = Webhook.verify_standard(@body, std_headers(sig), @std_secret, now_ms: @now_s * 1000)
    end

    test "rejections" do
      good = std_sign(@key, "msg_1", @now_s, @body)
      now = [now_ms: @now_s * 1000]

      assert {:error, :signature_mismatch} =
               Webhook.verify_standard(@body <> " ", std_headers(good), @std_secret, now)

      assert {:error, :signature_mismatch} =
               Webhook.verify_standard(@body, std_headers(std_sign("other", "msg_1", @now_s, @body)), @std_secret, now)

      assert {:error, :stale_timestamp} =
               Webhook.verify_standard(@body, std_headers(good), @std_secret, now_ms: (@now_s + 301) * 1000)

      assert {:error, :stale_timestamp} =
               Webhook.verify_standard(@body, List.keyreplace(std_headers(good), "webhook-timestamp", 0, {"webhook-timestamp", "abc"}), @std_secret, now)

      assert {:error, :missing_headers} = Webhook.verify_standard(@body, [], @std_secret, now)
      assert {:error, :malformed_signature} = Webhook.verify_standard(@body, std_headers("v2,abc"), @std_secret, now)
    end
  end
end
