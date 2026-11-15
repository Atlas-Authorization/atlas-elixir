defmodule AtlasAuth.WebhookDedupeTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.WebhookDedupe
  alias AtlasAuth.WebhookDedupe.MemoryStore

  @secret "whsec_test_secret"
  @now 1_757_937_600_000
  @body ~s({"id":"evt_1","type":"user.updated","data":{"id":"user_1"}})

  defp sign(id, ts, body) do
    mac = :crypto.mac(:hmac, :sha256, @secret, "#{id}.#{ts}.#{body}") |> Base.encode64()
    [{"atlas-id", id}, {"atlas-timestamp", Integer.to_string(ts)}, {"atlas-signature", "v1," <> mac}]
  end

  setup do
    {:ok, pid} = MemoryStore.start_link([])
    {:ok, store: {MemoryStore, pid}}
  end

  test "the first delivery is fresh, a retry is a duplicate", %{store: store} do
    headers = sign("evt_1", @now, @body)
    assert {:ok, %{duplicate: false, delivery_id: "evt_1", event: %{"type" => "user.updated"}}} = WebhookDedupe.verify_and_dedupe(@body, headers, @secret, store, now_ms: @now)
    assert {:ok, %{duplicate: true}} = WebhookDedupe.verify_and_dedupe(@body, headers, @secret, store, now_ms: @now)
  end

  test "release lets a retry through", %{store: store} do
    headers = sign("evt_1", @now, @body)
    {:ok, %{release: release}} = WebhookDedupe.verify_and_dedupe(@body, headers, @secret, store, now_ms: @now)
    release.()
    assert {:ok, %{duplicate: false}} = WebhookDedupe.verify_and_dedupe(@body, headers, @secret, store, now_ms: @now)
  end

  test "an unverified delivery never touches the store", %{store: store} do
    bad = sign("evt_1", @now, "other body")
    assert {:error, :signature_mismatch} = WebhookDedupe.verify_and_dedupe(@body, bad, @secret, store, now_ms: @now)
    assert {:ok, %{duplicate: false}} = WebhookDedupe.verify_and_dedupe(@body, sign("evt_1", @now, @body), @secret, store, now_ms: @now)
  end

  test "a non-JSON body is :invalid_body", %{store: store} do
    body = "not json"
    assert {:error, :invalid_body} = WebhookDedupe.verify_and_dedupe(body, sign("evt_2", @now, body), @secret, store, now_ms: @now)
  end

  test "the memory store forgets after the ttl" do
    {:ok, clock} = Agent.start_link(fn -> 0 end)
    {:ok, pid} = MemoryStore.start_link(now_ms: fn -> Agent.get(clock, & &1) end)
    assert MemoryStore.set_if_absent(pid, "k", 10)
    refute MemoryStore.set_if_absent(pid, "k", 10)
    Agent.update(clock, fn _ -> 10_001 end)
    assert MemoryStore.set_if_absent(pid, "k", 10)
  end
end
