defmodule AtlasAuth.SpSurfaceTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.{Claims, Constants, Errors, KeyFormat, Privacy, Trace, Webhook, WebhookEvents}

  @secret "whsec_test_secret"
  @url "https://app.example.com/hooks/atlas"
  @now 1_757_937_600_000
  @body ~s({"id":"evt_1","type":"privacy_request.completed","data":{"id":"prq_1","status":"completed"}})

  defp mac(data), do: :crypto.mac(:hmac, :sha256, @secret, data) |> Base.encode64()

  defp headers(sig, id \\ "evt_1", ts \\ @now, extra \\ []) do
    [{"atlas-id", id}, {"atlas-timestamp", Integer.to_string(ts)}, {"atlas-signature", sig}] ++ extra
  end

  describe "KeyFormat" do
    test "accepts suite and legacy formats" do
      assert KeyFormat.secret_key?("atlas_live_sk_abc123")
      assert KeyFormat.secret_key?("atlas_test_sk_abc123")
      assert KeyFormat.secret_key?("sk_live_abc")
      assert KeyFormat.secret_key?("sk_test_abc")
      assert KeyFormat.platform_key?("atlas_live_psk_x")
      assert KeyFormat.platform_key?("psk_live_x")
      assert KeyFormat.platform_key?("psk_x")
      assert KeyFormat.publishable_key?("pk_live_x")
      assert KeyFormat.webhook_secret?("whsec_abc")
      assert KeyFormat.webhook_secret?("atlas_live_whsec_abc")
      assert KeyFormat.partner_link_secret?("atlas_live_pl_abc")
      assert KeyFormat.access_token?("atlas_live_at_abc")
    end

    test "rejects anything else" do
      refute KeyFormat.secret_key?("atlas_live_pk_abc")
      refute KeyFormat.secret_key?("atlas_dev_sk_abc")
      refute KeyFormat.secret_key?("atlas_live_sk")
      refute KeyFormat.secret_key?("sk_abc")
      refute KeyFormat.secret_key?("pk_live_x")
      refute KeyFormat.publishable_key?("atlas_live_pk_x")
      refute KeyFormat.secret_key?(nil)
      assert :error = KeyFormat.parse("whatever")
    end

    test "parse reports kind, environment and format" do
      assert {:ok, %{kind: :secret, environment: "live", suite: true}} = KeyFormat.parse("atlas_live_sk_x_y")
      assert {:ok, %{kind: :publishable, environment: "test", suite: false}} = KeyFormat.parse("pk_test_x")
      assert {:ok, %{kind: :platform, environment: nil, suite: false}} = KeyFormat.parse("psk_x")
    end
  end

  describe "Trace" do
    test "new is a valid sampled traceparent" do
      tp = Trace.new()
      assert tp =~ ~r/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/
      assert {:ok, %{trace_id: t, span_id: s, flags: "01"}} = Trace.parse(tp)
      assert byte_size(t) == 32 and byte_size(s) == 16
      refute Trace.new() == tp
    end

    test "parse rejects malformed and all-zero ids" do
      assert :error = Trace.parse("nope")
      assert :error = Trace.parse("00-" <> String.duplicate("0", 32) <> "-" <> String.duplicate("a", 16) <> "-01")
      assert :error = Trace.parse("00-" <> String.duplicate("a", 32) <> "-" <> String.duplicate("0", 16) <> "-01")
      assert :error = Trace.parse(nil)

      assert {:ok, %{flags: "00"}} =
               Trace.parse(" 00-" <> String.duplicate("A", 32) <> "-" <> String.duplicate("b", 16) <> "-00 ")
    end

    test "from_headers" do
      tp = Trace.new()
      assert Trace.from_headers([{"Traceparent", tp}]) == tp
      assert Trace.from_headers(%{"TRACEPARENT" => tp}) == tp
      assert Trace.from_headers([{"traceparent", "bad"}]) == nil
      assert Trace.from_headers([]) == nil
    end
  end

  describe "Webhook.verify_url/5 (signature v2)" do
    defp v1(id \\ "evt_1", ts \\ @now), do: "v1," <> mac("#{id}.#{ts}.#{@body}")
    defp v2(url \\ @url, id \\ "evt_1", ts \\ @now), do: "v2," <> mac("#{id}.#{ts}.#{url}.#{@body}")

    test "accepts a v2 entry bound to the URL" do
      assert {:ok, %{delivery_id: "evt_1", timestamp: @now, event: %{"id" => "evt_1"}}} =
               Webhook.verify_url(@body, headers(v2()), @secret, @url, now_ms: @now)
    end

    test "rejects a v2 entry replayed to another URL" do
      assert {:error, :signature_mismatch} =
               Webhook.verify_url(@body, headers(v2()), @secret, "https://evil.example/x", now_ms: @now)
    end

    test "a v1 entry still verifies unless require_v2" do
      assert {:ok, _} = Webhook.verify_url(@body, headers(v1()), @secret, @url, now_ms: @now)

      assert {:error, :malformed_signature} =
               Webhook.verify_url(@body, headers(v1()), @secret, @url, now_ms: @now, require_v2: true)

      assert {:ok, _} =
               Webhook.verify_url(@body, headers(v1() <> " " <> v2()), @secret, @url, now_ms: @now, require_v2: true)
    end

    test "unknown versions are ignored" do
      assert {:ok, _} = Webhook.verify_url(@body, headers("v9,abc " <> v2()), @secret, @url, now_ms: @now)
      assert {:error, :malformed_signature} = Webhook.verify_url(@body, headers("v9,abc"), @secret, @url, now_ms: @now)
    end

    test "stale timestamp, missing headers, tampered body" do
      old = @now - 360_000
      assert {:error, :stale_timestamp} = Webhook.verify_url(@body, headers(v2(@url, "evt_1", old), "evt_1", old), @secret, @url, now_ms: @now)
      assert {:error, :missing_headers} = Webhook.verify_url(@body, [], @secret, @url, now_ms: @now)
      assert {:error, :signature_mismatch} = Webhook.verify_url(@body <> " ", headers(v2()), @secret, @url, now_ms: @now)
    end

    test "plain verify/4 ignores v2 entries" do
      assert {:error, :malformed_signature} = Webhook.verify(@body, headers(v2()), @secret, now_ms: @now)
    end
  end

  describe "WebhookEvents" do
    test "canonical, deprecated and spellings" do
      assert WebhookEvents.canonical("organizationMembership.created") == "organization_membership.created"
      assert WebhookEvents.canonical("session.ended") == "session.revoked"
      assert WebhookEvents.canonical("user.created") == "user.created"
      assert WebhookEvents.deprecated?("billing.trial.started")
      refute WebhookEvents.deprecated?("billing_trial.started")
      assert map_size(WebhookEvents.aliases()) == 39

      assert WebhookEvents.spellings("session.removed") == ["session.revoked", "session.ended", "session.removed"]
      assert WebhookEvents.spellings("user.created") == ["user.created"]
      assert {"user.deletion_canceled", :companion} = WebhookEvents.aliases()["user.deletion_cancelled"]
      assert {"scim_token.created", :rename} = WebhookEvents.aliases()["scimToken.created"]
    end

    test "event name constants" do
      assert WebhookEvents.webhook_endpoint_failing() == "webhook_endpoint.failing"
      assert WebhookEvents.delivery_target_recovered() == "delivery_target.recovered"
      assert WebhookEvents.secret_key_expiring() == "secret_key.expiring"
      assert WebhookEvents.status_incident_resolved() == "status.incident.resolved"
      assert WebhookEvents.privacy_request_completed() == "privacy_request.completed"
      assert WebhookEvents.user_deletion_scheduled() == "user.deletion_scheduled"
      assert Constants.scope_webhooks_reveal() == "webhooks:reveal"
      assert "referally" in Constants.referral_provider_aliases()
      assert Constants.referral_provider() == "referalli"
    end
  end

  describe "Errors" do
    test "codes and scope tolerance" do
      assert Errors.insufficient_scope() == "INSUFFICIENT_SCOPE"
      assert Errors.insufficient_scope?("INSUFFICIENT_SCOPE")
      assert Errors.insufficient_scope?("SCOPE_MISSING")
      refute Errors.insufficient_scope?("STEP_UP_REQUIRED")
      assert Errors.step_up_required() == "STEP_UP_REQUIRED"
    end

    test "parse reads scope and route hints" do
      body = %{
        "errors" => [
          %{
            "code" => "ROUTE_NOT_FOUND",
            "message" => "no route",
            "did_you_mean" => ["/v1/users"],
            "allowed_methods" => ["GET"],
            "docs_url" => "https://atlasauth.net/errors/ROUTE_NOT_FOUND"
          }
        ]
      }

      assert %{code: "ROUTE_NOT_FOUND", did_you_mean: ["/v1/users"], allowed_methods: ["GET"]} = Errors.parse(body)

      scope = Errors.parse(%{"errors" => [%{"code" => "SCOPE_MISSING", "message" => "m", "meta" => %{"required_scope" => "privacy:execute"}}]})
      assert scope.required_scope == "privacy:execute"
      assert Errors.insufficient_scope?(scope)
      assert Errors.parse(%{"errors" => []}) == nil
    end
  end

  describe "Privacy.verify_call/4" do
    test "verifies a signed event and surfaces traceparent" do
      tp = Trace.new()
      hs = headers(v1(), "evt_1", @now, [{"Traceparent", tp}])
      assert {:ok, call} = Privacy.verify_call(@body, hs, @secret, now_ms: @now)
      assert call.delivery_id == "evt_1"
      assert call.traceparent == tp
      assert call.body == @body
      assert call.event["type"] == "privacy_request.completed"
      assert %{"id" => "prq_1"} = Privacy.request_from_event(call.event)
    end

    test "a signed case call has no event" do
      body = ~s({"case":"c1","subject":"u1"})
      sig = "v1," <> mac("evt_2.#{@now}.#{body}")
      assert {:ok, call} = Privacy.verify_call(body, headers(sig, "evt_2"), @secret, now_ms: @now)
      assert call.event == nil
      assert call.traceparent == nil
      assert Privacy.request_from_event(call.event) == nil
    end

    test "rejects a bad signature" do
      assert {:error, :signature_mismatch} =
               Privacy.verify_call(@body, headers("v1," <> Base.encode64("x")), @secret, now_ms: @now)
    end

    test "constants" do
      assert "restriction" in Privacy.types()
      assert "completed_with_retention" in Privacy.statuses()
      assert Privacy.scope_execute() == "privacy:execute"
      assert Privacy.scope_grants_revoke() == "privacy:grants:revoke"
    end
  end

  describe "Claims org / sso" do
    test "reads orgs and sso claims" do
      claims =
        Claims.from_map(%{
          "sub" => "u1",
          "orgs" => [%{"id" => "org_1", "role" => "admin"}, "junk"],
          "sso_connection_id" => "sso_1",
          "sso_tenant_id" => "t1",
          "sso_issuer" => "https://idp.example",
          "sso_domain" => "example.com"
        })

      assert claims.orgs == [%{"id" => "org_1", "role" => "admin"}]
      assert claims.sso_connection_id == "sso_1"
      assert claims.sso_tenant_id == "t1"
      assert claims.sso_issuer == "https://idp.example"
      assert claims.sso_domain == "example.com"
    end

    test "defaults are empty" do
      claims = Claims.from_map(%{"sub" => "u1"})
      assert claims.orgs == [] and claims.sso_connection_id == nil
    end
  end
end
