defmodule AtlasAuth.PolicySourceTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{Claims, Constants, PolicySource}

  # Vectors shared with the TypeScript reference (packages/backend policy-source).
  @secret "whsec_test_secret_0123456789"
  @ts 1_760_000_000_000
  @sig_key "YfnQOCSMi2qm50WuVdA/aIV4avYpC6Hms9wdKrZcgHI="
  @sig_full "KT51ui3s0XNh9yr/2FedfQgVWCpYAMLQRKOvohc9VTM="
  @sig_event "1q9qbfr02vQN6Xwsj0NjzR65jJiWo39qg8+JutS9ebs="

  defp verify(path, sig, extra \\ []) do
    headers = [
      {"atlas-id", "msg_01"},
      {"atlas-timestamp", Integer.to_string(@ts)},
      {"atlas-signature", sig},
      {"atlas-policies-version", "2026-10-24"}
    ]

    PolicySource.verify_feed_request(
      Keyword.merge(
        [method: "GET", path_and_query: path, headers: headers, secret: @secret, now_ms: @ts],
        extra
      )
    )
  end

  test "verifies Atlas's feed request against the reference vectors" do
    assert {:ok,
            %{key: "tos", delivery_id: "msg_01", timestamp: @ts, protocol_version: "2026-10-24"}} =
             verify("/atlas/policies?key=tos", "v1," <> @sig_key, now_ms: @ts + 1000)

    assert {:ok, %{key: nil}} = verify("/atlas/policies", "v1," <> @sig_full, method: "get")
  end

  test "accepts any of several v1 values and ignores other versions" do
    assert {:ok, _} = verify("/atlas/policies?key=tos", "v1,AAAA v2,zzzz v1," <> @sig_key)
  end

  test "accepts headers as a map" do
    headers = %{
      "Atlas-Id" => "msg_01",
      "Atlas-Timestamp" => Integer.to_string(@ts),
      "Atlas-Signature" => "v1," <> @sig_key
    }

    assert {:ok, %{key: "tos"}} =
             PolicySource.verify_feed_request(
               path_and_query: "/atlas/policies?key=tos",
               headers: headers,
               secret: @secret,
               now_ms: @ts
             )
  end

  test "refuses bad requests" do
    good = "v1," <> @sig_key
    assert {:error, :signature_mismatch} = verify("/atlas/policies?key=other", good)

    assert {:error, :signature_mismatch} =
             verify("/atlas/policies?key=tos", good, secret: "wrong")

    assert {:error, :stale_timestamp} =
             verify("/atlas/policies?key=tos", good, now_ms: @ts + 300_001)

    assert {:ok, _} = verify("/atlas/policies?key=tos", good, now_ms: @ts + 300_000)
    assert {:error, :malformed_signature} = verify("/x", "v2,AA")
    assert {:error, :wrong_method} = verify("/x", "v1,AA", method: "POST")

    assert {:error, :missing_headers} =
             PolicySource.verify_feed_request(path_and_query: "/x", headers: [], secret: @secret)
  end

  test "signs events like the reference" do
    body =
      ~s({"occurred_at":"2026-10-24T00:00:00.000Z","type":"policy.published","key":"tos","version":"2026-10-24"})

    signed = PolicySource.sign_body(body, secret: @secret, id: "evt_1", timestamp_ms: @ts)
    assert signed.body == body
    assert {"atlas-signature", "v1," <> @sig_event} in signed.headers
    assert {"atlas-id", "evt_1"} in signed.headers
    assert {"atlas-timestamp", Integer.to_string(@ts)} in signed.headers
  end

  test "built events carry their fields and verify with the webhook verifier" do
    signed = PolicySource.sign_published("tos", "2026-10-24", @secret)
    decoded = Jason.decode!(signed.body)
    assert decoded["type"] == "policy.published"
    assert decoded["version"] == "2026-10-24"
    assert is_binary(decoded["occurred_at"])
    assert {"atlas-id", "evt_" <> _} = List.keyfind(signed.headers, "atlas-id", 0)

    assert {:ok, %{event: %{"key" => "tos"}}} =
             AtlasAuth.Webhook.verify(signed.body, signed.headers, @secret)

    retired = PolicySource.sign_retired("tos", @secret)
    refute Map.has_key?(Jason.decode!(retired.body), "version")

    assert_raise ArgumentError, fn ->
      PolicySource.sign_event(%{type: "policy.published", key: "tos"}, secret: @secret)
    end
  end

  test "the pol claim and constants" do
    claims =
      Claims.from_map(%{"iss" => "i", "sub" => "s", "exp" => 1, "pol" => %{"tos" => "2026-10-24"}})

    assert Claims.pol(claims) == %{"tos" => "2026-10-24"}
    assert Claims.has_accepted_policy?(claims, "tos", "2026-10-24")
    refute Claims.has_accepted_policy?(claims, "tos", "old")
    assert Claims.pol(Claims.from_map(%{"iss" => "i", "sub" => "s", "exp" => 1})) == %{}
    assert Constants.webhook_user_policy_accepted() == "user.policy_accepted"
    assert Constants.webhook_policy_version_published() == "policy.version_published"
    assert PolicySource.protocol_version() == "2026-10-24"
  end
end
