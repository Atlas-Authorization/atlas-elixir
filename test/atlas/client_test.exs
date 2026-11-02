defmodule Atlas.ClientTest do
  use ExUnit.Case, async: true

  defp client(stub), do: Atlas.new("sk_test_abc", req_options: [plug: {Req.Test, stub}, retry: false])

  test "sends bearer auth, JSON body and idempotency key; decodes the response" do
    Req.Test.stub(:create, fn conn ->
      {:ok, raw, conn} = Plug.Conn.read_body(conn)
      assert conn.method == "POST"
      assert conn.request_path == "/v1/users"
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer sk_test_abc"]
      assert Plug.Conn.get_req_header(conn, "idempotency-key") == ["k1"]
      assert Jason.decode!(raw) == %{"email_address" => "a@example.com"}
      conn |> Plug.Conn.put_status(201) |> Req.Test.json(%{"id" => "user_1"})
    end)

    assert {:ok, %{"id" => "user_1"}} =
             Atlas.Users.create(client(:create), %{"email_address" => "a@example.com"}, idempotency_key: "k1")
  end

  test "path parameters are percent-encoded and query params are sent" do
    Req.Test.stub(:enc, fn conn ->
      assert conn.request_path == "/v1/users/a%2Fb%20c"
      assert conn.query_string == "expand=orgs"
      Req.Test.json(conn, %{})
    end)

    assert {:ok, _} = Atlas.Users.get(client(:enc), "a/b c", params: [expand: "orgs"])
  end

  test "an error response becomes %Atlas.Error{} with the Atlas code and request id" do
    Req.Test.stub(:err, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("x-request-id", "req_9")
      |> Plug.Conn.put_status(403)
      |> Req.Test.json(%{"errors" => [%{"code" => "INSUFFICIENT_SCOPE", "message" => "no", "meta" => %{"required_scope" => "users:write"}}]})
    end)

    assert {:error, %Atlas.Error{status: 403, code: "INSUFFICIENT_SCOPE", required_scope: "users:write", request_id: "req_9"}} =
             Atlas.Users.get(client(:err), "u1")
  end

  test "a 204 is {:ok, nil} and a non-JSON error still yields an Atlas.Error" do
    Req.Test.stub(:nocontent, fn conn -> Plug.Conn.send_resp(conn, 204, "") end)
    assert {:ok, nil} = Atlas.Users.delete(client(:nocontent), "u1")

    Req.Test.stub(:html, fn conn -> Plug.Conn.send_resp(conn, 502, "bad gateway") end)
    assert {:error, %Atlas.Error{status: 502, code: "HTTP_502"}} = Atlas.Users.get(client(:html), "u1")
  end

  test "a transport failure is an Atlas.Error with no status" do
    Req.Test.stub(:down, fn conn -> Req.Test.transport_error(conn, :econnrefused) end)
    assert {:error, %Atlas.Error{status: nil, code: "TRANSPORT_ERROR"}} = Atlas.Users.get(client(:down), "u1")
  end

  test "stream_list follows next_cursor across pages and stops when has_more is false" do
    Req.Test.stub(:pages, fn conn ->
      case URI.decode_query(conn.query_string)["starting_after"] do
        nil -> Req.Test.json(conn, %{"data" => [%{"id" => "u1"}, %{"id" => "u2"}], "has_more" => true, "next_cursor" => "c2"})
        "c2" -> Req.Test.json(conn, %{"data" => [%{"id" => "u3"}], "has_more" => false, "next_cursor" => nil})
      end
    end)

    assert ["u1", "u2", "u3"] == :pages |> client() |> Atlas.Users.stream_list() |> Enum.map(& &1["id"])
  end

  test "stream_list falls back to the last id and raises Atlas.Error on a failed page" do
    Req.Test.stub(:fallback, fn conn ->
      case URI.decode_query(conn.query_string)["starting_after"] do
        nil -> Req.Test.json(conn, %{"data" => [%{"id" => "u1"}], "has_more" => true})
        "u1" -> conn |> Plug.Conn.put_status(500) |> Req.Test.json(%{"errors" => [%{"code" => "INTERNAL", "message" => "x"}]})
      end
    end)

    assert_raise Atlas.Error, fn -> :fallback |> client() |> Atlas.Users.stream_list() |> Enum.to_list() end
  end

  test "non-JSON success bodies are returned raw" do
    Req.Test.stub(:raw, fn conn ->
      conn |> Plug.Conn.put_resp_content_type("application/gzip") |> Plug.Conn.send_resp(200, <<31, 139, 8>>)
    end)

    assert {:ok, <<31, 139, 8>>} = Atlas.Users.get(client(:raw), "u1")
  end

  # Records {method, path, query, body} of each request and answers {}.
  defp capture(name) do
    me = self()

    Req.Test.stub(name, fn conn ->
      {:ok, raw, conn} = Plug.Conn.read_body(conn)
      send(me, {:req, conn.method, conn.request_path, URI.decode_query(conn.query_string), if(raw == "", do: nil, else: Jason.decode!(raw))})
      Req.Test.json(conn, %{})
    end)

    client(name)
  end

  test "2026-11-01 operations send the documented method, path, query and body" do
    c = capture(:cal)

    assert {:ok, _} = Atlas.Organizations.get_by_domain(c, "a@acme.com", params: [include_unverified: true])
    assert_received {:req, "GET", "/v1/organizations/by_domain/a%40acme.com", %{"include_unverified" => "true"}, nil}

    assert {:ok, _} = Atlas.Organizations.list(c, params: [{"external_id", "cus_1"}, {"metadata[plan]", "pro"}])
    assert_received {:req, "GET", "/v1/organizations", %{"external_id" => "cus_1", "metadata[plan]" => "pro"}, nil}

    assert {:ok, _} = Atlas.Organizations.get_policy(c, "org_1")
    assert_received {:req, "GET", "/v1/organizations/org_1/policy", _, nil}

    assert {:ok, _} = Atlas.Organizations.post_domains_verification_email(c, "org_1", "dom_1", %{"address" => "hostmaster"})
    assert_received {:req, "POST", "/v1/organizations/org_1/domains/dom_1/verification_email", _, %{"address" => "hostmaster"}}

    assert {:ok, _} = Atlas.Organizations.post_domains_verify(c, "org_1", "dom_1", %{"method" => "email", "code" => "123456"})
    assert_received {:req, "POST", "/v1/organizations/org_1/domains/dom_1/verify", _, %{"method" => "email", "code" => "123456"}}

    assert {:ok, _} = Atlas.Organizations.post_domains_verify(c, "org_1", "dom_1")
    assert_received {:req, "POST", "/v1/organizations/org_1/domains/dom_1/verify", _, %{}}

    jwt = %{"organization_id" => "org_1", "status" => "active", "jwks_uri" => "https://idp.example.com/jwks", "issuer" => "https://idp.example.com", "audience" => "atlas"}
    assert {:ok, _} = Atlas.JwtConnections.create(c, jwt, idempotency_key: "j1")
    assert_received {:req, "POST", "/v1/jwt_connections", _, ^jwt}

    assert {:ok, _} = Atlas.JwtConnections.update(c, "jwtc_1", %{"max_age_seconds" => 60})
    assert_received {:req, "PATCH", "/v1/jwt_connections/jwtc_1", _, %{"max_age_seconds" => 60}}

    assert {:ok, _} = Atlas.JwtConnections.list(c)
    assert_received {:req, "GET", "/v1/jwt_connections", _, nil}

    assert {:ok, _} = Atlas.JwtConnections.delete(c, "jwtc_1")
    assert_received {:req, "DELETE", "/v1/jwt_connections/jwtc_1", _, nil}

    assert {:ok, _} = Atlas.PlatformApps.reveal_initial_secret(c, "app_1", params: [dry_run: true])
    assert_received {:req, "POST", "/v1/platform/apps/app_1/initial_secret/reveal", %{"dry_run" => "true"}, nil}
  end

  test "2026-11-02 operations: client logout, refresh_touches_session, add_redirect_origins, captcha site_key" do
    c = capture(:cal2)

    assert {:ok, _} = Atlas.OauthClients.post_logout(c, "oac_1", %{"sid" => "sess_1"}, idempotency_key: "l1")
    assert_received {:req, "POST", "/v1/oauth_clients/oac_1/logout", _, %{"sid" => "sess_1"}}

    create = %{"name" => "App", "redirect_uris" => ["https://app.example.com/cb"], "first_party" => true,
               "refresh_touches_session" => true, "add_redirect_origins" => true}
    assert {:ok, _} = Atlas.OauthClients.create(c, create)
    assert_received {:req, "POST", "/v1/oauth_clients", _, ^create}

    assert {:ok, _} = Atlas.OauthClients.update(c, "oac_1", %{"refresh_touches_session" => false, "add_redirect_origins" => true})
    assert_received {:req, "PATCH", "/v1/oauth_clients/oac_1", _, %{"refresh_touches_session" => false, "add_redirect_origins" => true}}

    captcha = %{"secret" => "0x4AAA", "provider" => "turnstile", "site_key" => "0x4BBB"}
    assert {:ok, _} = Atlas.Instance.put_captcha_secret(c, captcha)
    assert_received {:req, "PUT", "/v1/instance/captcha_secret", _, ^captcha}
  end

  test "2026-11-02 second round: preflight acks, secret reveal, require_verified_email, invitation expiry, app filters" do
    c = capture(:adv)

    assert {:ok, _} = Atlas.Instance.get_preflight_acks(c)
    assert_received {:req, "GET", "/v1/instance/preflight/acks", _, nil}

    ack = %{"reason" => "staging only", "expires_at" => "2026-12-01T00:00:00Z"}
    assert {:ok, _} = Atlas.Instance.put_preflight_acks(c, "pkce_not_required", ack, params: [dry_run: true])
    assert_received {:req, "PUT", "/v1/instance/preflight/acks/pkce_not_required", %{"dry_run" => "true"}, ^ack}

    assert {:ok, _} = Atlas.Instance.delete_preflight_acks(c, "pkce_not_required")
    assert_received {:req, "DELETE", "/v1/instance/preflight/acks/pkce_not_required", _, nil}

    assert {:ok, _} = Atlas.OauthClients.post_secret_reveal(c, "oac_1")
    assert_received {:req, "POST", "/v1/oauth_clients/oac_1/secret/reveal", _, nil}

    create = %{"name" => "App", "redirect_uris" => ["https://app.example.com/cb"], "client_secret" => String.duplicate("s", 40), "require_verified_email" => true}
    assert {:ok, _} = Atlas.OauthClients.create(c, create)
    assert_received {:req, "POST", "/v1/oauth_clients", _, ^create}

    assert {:ok, _} = Atlas.OauthClients.update(c, "oac_1", %{"require_verified_email" => false})
    assert_received {:req, "PATCH", "/v1/oauth_clients/oac_1", _, %{"require_verified_email" => false}}

    inv = %{"email_address" => "a@example.com", "expires_in_days" => 30}
    assert {:ok, _} = Atlas.Invitations.create(c, inv)
    assert_received {:req, "POST", "/v1/invitations", _, ^inv}

    assert {:ok, _} = Atlas.Instance.update_hooks_before_user_create(c, %{"fail_closed" => true})
    assert_received {:req, "PATCH", "/v1/instance/hooks/before_user_create", _, %{"fail_closed" => true}}

    assert {:ok, _} = Atlas.PlatformApps.list(c, params: [name_prefix: "acme", external_ref: "acme/prod", limit: 50])
    assert_received {:req, "GET", "/v1/platform/apps", %{"name_prefix" => "acme", "external_ref" => "acme/prod", "limit" => "50"}, nil}

    assert AtlasAuth.WebhookEvents.session_expired() == "session.expired"
    assert AtlasAuth.WebhookEvents.invitation_accepted() == "invitation.accepted"
  end
end
