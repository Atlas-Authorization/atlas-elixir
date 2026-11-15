defmodule AtlasAuth.KeyMirrorTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.KeyMirror
  alias AtlasAuth.KeyMirror.MemoryStore

  defmodule FakeApi do
    # Handlers live in the test process dictionary: every call runs in the test process.
    defp h(name), do: Process.get({:fake_api, name}) || fn _ -> {:ok, %{}} end
    def create(_c, body, _opts), do: h(:create).(body)
    def delete(_c, id, _opts \\ []), do: h(:delete).(id)
    def get_revoked(_c, opts), do: h(:get_revoked).(opts[:params])
    def post_verify(_c, body, _opts \\ []), do: h(:post_verify).(body)
    def get(_c, id, _opts \\ []), do: h(:get).(id)
    def post_rotate(_c, id, body, _opts), do: h(:post_rotate).({id, body})
  end

  @now 1_700_000_000_000

  setup do
    {:ok, pid} = MemoryStore.start_link()
    {:ok, clock} = Agent.start_link(fn -> @now end)

    mirror = fn extra ->
      KeyMirror.new([store: {MemoryStore, pid}, api: FakeApi, now_ms: fn -> Agent.get(clock, & &1) end] ++ extra)
    end

    {:ok, store: pid, clock: clock, mirror: mirror}
  end

  defp api(name, fun), do: Process.put({:fake_api, name}, fun)

  defp minted(overrides \\ %{}) do
    Map.merge(
      %{"id" => "eak_1", "secret" => "ak_secret_1", "prefix" => "ak_secret", "subject_type" => "user", "subject_id" => "usr_1", "name" => "ci", "scopes" => ["read"], "expires_at" => nil, "revoked_at" => nil},
      overrides
    )
  end

  test "mint stores only the hash; verify answers locally and checks scopes", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted()} end)
    assert {:ok, %{"secret" => "ak_secret_1"}} = KeyMirror.mint(m, %{name: "ci"})
    assert {:ok, %{key: key, effective_scopes: ["read"]}} = KeyMirror.verify(m, "ak_secret_1")
    assert key.hash == KeyMirror.hash_secret("ak_secret_1")
    refute Map.has_key?(key, :secret)
    assert {:error, {:insufficient_scope, ["write"]}} = KeyMirror.verify(m, "ak_secret_1", required_scopes: ["read", "write"])
    assert {:error, :invalid} = KeyMirror.verify(m, "nope")
    assert {:error, :invalid} = KeyMirror.verify(m, "")
  end

  test "scope implications expand held scopes", %{mirror: mirror} do
    m = mirror.(scope_implications: %{"admin" => ["read", "write"], "write" => ["read"]})
    api(:create, fn _ -> {:ok, minted(%{"scopes" => ["admin"]})} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert {:ok, %{effective_scopes: ["admin", "read", "write"]}} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "revoke is local first and tolerates a 404 from Atlas", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted()} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    api(:delete, fn _ -> {:error, %Atlas.Error{status: 404, code: "NOT_FOUND", message: "x"}} end)
    assert :ok = KeyMirror.revoke(m, "eak_1")
    assert {:error, :invalid} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "revoke returns other Atlas errors but the key is already dead locally", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted()} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    api(:delete, fn _ -> {:error, %Atlas.Error{status: 500, code: "X", message: "x"}} end)
    assert {:error, %Atlas.Error{status: 500}} = KeyMirror.revoke(m, "eak_1")
    assert {:error, :invalid} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "an expired key is refused", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted(%{"expires_at" => @now - 1})} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert {:error, :invalid} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "allowed_ips needs the caller's address and matches CIDR ranges", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted(%{"allowed_ips" => ["10.0.0.0/8", "2001:db8::/32"]})} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert {:error, :client_ip_required} = KeyMirror.verify(m, "ak_secret_1")
    assert {:error, :ip_not_allowed} = KeyMirror.verify(m, "ak_secret_1", client_ip: "192.168.1.1")
    assert {:ok, _} = KeyMirror.verify(m, "ak_secret_1", client_ip: "10.1.2.3")
    assert {:ok, _} = KeyMirror.verify(m, "ak_secret_1", client_ip: "2001:db8::1")
    refute KeyMirror.ip_in_allowlist?("garbage", ["10.0.0.0/8"])
    assert KeyMirror.ip_in_allowlist?("1.2.3.4", ["1.2.3.4"])
  end

  test "sync consumes the revocation feed and records the cursor and time", %{mirror: mirror, store: store} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted()} end)
    {:ok, _} = KeyMirror.mint(m, %{})

    api(:get_revoked, fn params ->
      assert params[:limit] == 100
      {:ok, %{"data" => [%{"id" => "eak_1", "revoked_at" => @now - 5, "revoked_reason" => "user_banned"}], "has_more" => false, "next_cursor" => "c9"}}
    end)

    assert {:ok, %{revoked: 1}} = KeyMirror.sync(m)
    assert {:error, :invalid} = KeyMirror.verify(m, "ak_secret_1")
    assert MemoryStore.get_cursor(store) == "c9"
    assert KeyMirror.last_sync_at(m) == @now
    assert MemoryStore.get(store, "eak_1").revoked_reason == "user_banned"
  end

  test "max_staleness_ms refuses until synced, then serves, then refuses again", %{mirror: mirror, clock: clock} do
    m = mirror.(max_staleness_ms: 1000)
    api(:create, fn _ -> {:ok, minted()} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert {:error, {:stale, nil}} = KeyMirror.verify(m, "ak_secret_1")
    api(:get_revoked, fn _ -> {:ok, %{"data" => [], "has_more" => false}} end)
    {:ok, _} = KeyMirror.sync(m)
    assert {:ok, %{stale: false}} = KeyMirror.verify(m, "ak_secret_1")
    Agent.update(clock, &(&1 + 5000))
    assert {:error, {:stale, @now}} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "serve_stale_for_ms answers from last data with stale: true and fires the callback", %{mirror: mirror, clock: clock} do
    test = self()
    m = mirror.(max_staleness_ms: 1000, serve_stale_for_ms: 10_000, on_serve_stale: fn i -> send(test, {:stale, i}) end)
    api(:create, fn _ -> {:ok, minted()} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    api(:get_revoked, fn _ -> {:ok, %{"data" => [], "has_more" => false}} end)
    {:ok, _} = KeyMirror.sync(m)
    Agent.update(clock, &(&1 + 5000))
    assert {:ok, %{stale: true}} = KeyMirror.verify(m, "ak_secret_1")
    assert_received {:stale, %{stale_for_ms: 4000}}
  end

  test "verify_at_atlas learns the hash of a legacy-imported key on first use", %{mirror: mirror} do
    m = mirror.(verify_at_atlas: true)
    api(:create, fn body ->
      assert body[:import][:hash_algorithm] == "bcrypt"
      {:ok, minted(%{"outcome" => "created"})}
    end)

    assert {:ok, %{"outcome" => "created"}} = KeyMirror.import_key(m, %{prefix: "ak_secret", bcrypt_hash: "$2b$x", name: "old"})
    api(:post_verify, fn _ -> {:ok, %{"valid" => true, "id" => "eak_1"}} end)
    api(:get, fn "eak_1" -> {:ok, minted()} end)
    assert {:ok, %{key: %{id: "eak_1"}}} = KeyMirror.verify(m, "ak_secret_1")
    api(:post_verify, fn _ -> flunk("second verify must be local") end)
    assert {:ok, _} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "import with a secret sends only its sha256", %{mirror: mirror} do
    m = mirror.([])

    api(:create, fn body ->
      assert body[:import][:secret_hash] == KeyMirror.hash_secret("ak_secret_1")
      assert body[:import][:hash_algorithm] == "sha256_hex"
      refute Map.has_key?(body, :secret)
      {:ok, minted()}
    end)

    assert {:ok, _} = KeyMirror.import_key(m, %{prefix: "ak_secret", secret: "ak_secret_1"})
    assert {:ok, _} = KeyMirror.verify(m, "ak_secret_1")
    assert {:error, :secret_or_hash_required} = KeyMirror.import_key(m, %{prefix: "p"})
  end

  test "a key bound to an organization is narrowed by the current membership", %{mirror: mirror} do
    membership = fn "usr_1", "org_1" -> %{"permissions" => ["read"]}; _, _ -> nil end
    m = mirror.(membership: membership)
    api(:create, fn _ -> {:ok, minted(%{"scopes" => ["read", "write"], "organization_id" => "org_1"})} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert {:ok, %{effective_scopes: ["read"], organization: %{"permissions" => ["read"]}}} = KeyMirror.verify(m, "ak_secret_1")
    gone = mirror.(membership: fn _, _ -> nil end)
    assert {:error, :invalid} = KeyMirror.verify(gone, "ak_secret_1")
  end

  test "a bound key with no membership source and no Atlas answer is :membership_unresolved", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted(%{"organization_id" => "org_1"})} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    api(:post_verify, fn _ -> {:error, %Atlas.Error{status: 500, code: "X", message: "x"}} end)
    assert {:error, :membership_unresolved} = KeyMirror.verify(m, "ak_secret_1")
  end

  test "webhooks revoke, restore, update and end memberships", %{mirror: mirror} do
    m = mirror.([])
    api(:create, fn _ -> {:ok, minted(%{"organization_id" => "org_1"})} end)
    {:ok, _} = KeyMirror.mint(m, %{})
    assert KeyMirror.apply_webhook(m, %{"type" => "api_key.updated", "data" => %{"id" => "eak_1", "name" => "renamed"}})
    refute KeyMirror.apply_webhook(m, %{"type" => "api_key.updated", "data" => %{"id" => "unknown"}})
    refute KeyMirror.apply_webhook(m, %{"type" => "user.created", "data" => %{}})
    assert KeyMirror.apply_webhook(m, %{"type" => "organization_membership.deleted", "data" => %{"user_id" => "usr_1", "organization_id" => "org_1"}})
    assert KeyMirror.apply_webhook(m, %{"type" => "api_key.restored", "data" => %{"id" => "eak_1"}})
    assert KeyMirror.apply_webhook(m, %{"type" => "api_key.revoked", "data" => %{"id" => "eak_1", "revoked_reason" => "x"}})
    refute KeyMirror.apply_webhook(m, %{"type" => "api_key.restored", "data" => %{"id" => "eak_missing"}})
  end

  test "scope helpers" do
    assert KeyMirror.permission_covers_scope?("*", "x")
    assert KeyMirror.permission_covers_scope?("billing:*", "billing:read")
    refute KeyMirror.permission_covers_scope?("billing:*", "orders:read")
    assert KeyMirror.intersect_scopes(["a", "b:x", "b:x"], ["b:*"]) == ["b:x"]
  end
end
