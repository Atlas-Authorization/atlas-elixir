defmodule AtlasAuth.ResourceRoleMirrorTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.ResourceRoleMirror, as: Mirror
  alias AtlasAuth.ResourceRoleMirror.MemoryStore

  @now 1_700_000_000_000

  @types [
    %{"key" => "folder", "inherit" => true, "roles" => [%{"key" => "owner", "permissions" => ["*"]}, %{"key" => "viewer", "permissions" => ["doc:read"]}]},
    %{"key" => "doc", "inherit" => true, "roles" => [%{"key" => "editor", "permissions" => ["doc:edit"], "includes" => ["reader"]}, %{"key" => "reader", "permissions" => ["doc:read"]}]},
    %{"key" => "locked", "inherit" => false, "roles" => []}
  ]

  @resources [
    %{"id" => "res_f", "type" => "folder", "external_id" => "f1", "parent_id" => nil},
    %{"id" => "res_d", "type" => "doc", "external_id" => "d1", "parent_id" => "res_f"},
    %{"id" => "res_l", "type" => "locked", "external_id" => "l1", "parent_id" => "res_f"}
  ]

  defp change(kind, id, resource, subject, role, inherit \\ true) do
    [st, sid] = String.split(subject, ":")
    %{"change" => kind, "assignment_id" => id, "resource_id" => resource, "subject" => %{"type" => st, "id" => sid}, "role" => role, "inherit" => inherit}
  end

  setup do
    {:ok, pid} = MemoryStore.start_link()
    {:ok, clock} = Agent.start_link(fn -> @now end)
    {:ok, feed} = Agent.start_link(fn -> [] end)

    api = %{
      types: fn -> {:ok, %{"data" => @types}} end,
      resources: fn _ -> {:ok, %{"data" => @resources, "has_more" => false}} end,
      changes: fn params -> {:ok, %{"data" => Agent.get(feed, & &1), "has_more" => false, "next_cursor" => "cur_#{params[:limit]}"}} end
    }

    new = fn extra -> Mirror.new([store: {MemoryStore, pid}, api: api, now_ms: fn -> Agent.get(clock, & &1) end] ++ extra) end
    {:ok, new: new, feed: feed, clock: clock, store: pid}
  end

  defp sync!(m) do
    {:ok, m, _} = Mirror.sync(m)
    m
  end

  test "a direct role grants its permissions; an unrelated user gets none", %{new: new, feed: feed} do
    Agent.update(feed, fn _ -> [change("created", "a1", "res_d", "user:u1", "editor")] end)
    m = sync!(new.([]))
    ref = %{type: "doc", external_id: "d1"}
    assert Mirror.can?(m, {:user, "u1"}, "doc:edit", ref)
    # `includes` follows
    assert Mirror.can?(m, {:user, "u1"}, "doc:read", ref)
    refute Mirror.can?(m, {:user, "u2"}, "doc:read", ref)
    assert %{allowed: true, resource_id: "res_d", grants: [%{role: "editor", inherited: false}]} = Mirror.check(m, {:user, "u1"}, "doc:edit", %{id: "res_d"})
  end

  test "inheritance from the parent, subject expansion through orgs and groups", %{new: new, feed: feed} do
    Agent.update(feed, fn _ -> [change("created", "a1", "res_f", "org:org1", "viewer"), change("created", "a2", "res_f", "group:eng", "owner")] end)
    m = sync!(new.([]))
    ref = %{id: "res_d"}
    refute Mirror.can?(m, {:user, "u1"}, "doc:read", ref)
    assert %{grants: [%{subject: "org:org1", inherited: true}]} = Mirror.check(m, {:user, "u1"}, "doc:read", ref, orgs: ["org1"])
    assert Mirror.can?(m, {:user, "u1"}, "anything", ref, groups: ["eng"])
  end

  test "a type that does not inherit stops the walk; an assignment with inherit: false is not inherited", %{new: new, feed: feed} do
    Agent.update(feed, fn _ -> [change("created", "a1", "res_f", "user:u1", "owner"), change("created", "a2", "res_f", "user:u2", "owner", false)] end)
    m = sync!(new.([]))
    assert Mirror.can?(m, {:user, "u1"}, "x", %{id: "res_d"})
    refute Mirror.can?(m, {:user, "u2"}, "x", %{id: "res_d"})
    # `locked` does not inherit, so the folder's owner grant is out of reach.
    refute Mirror.can?(m, {:user, "u1"}, "x", %{id: "res_l"})
  end

  test "deleted changes remove assignments; the cursor and sync time are stored", %{new: new, feed: feed, store: store} do
    Agent.update(feed, fn _ -> [change("created", "a1", "res_d", "user:u1", "editor")] end)
    m = sync!(new.([]))
    assert Mirror.can?(m, {:user, "u1"}, "doc:edit", %{id: "res_d"})
    assert MemoryStore.get_cursor(store) == "cur_500"
    assert Mirror.last_sync_at(m) == @now
    Agent.update(feed, fn _ -> [change("deleted", "a1", "res_d", "user:u1", "editor")] end)
    m = sync!(m)
    refute Mirror.can?(m, {:user, "u1"}, "doc:edit", %{id: "res_d"})
  end

  test "an unknown resource is code :unknown_resource", %{new: new} do
    m = sync!(new.([]))
    assert %{allowed: false, code: :unknown_resource} = Mirror.check(m, {:user, "u1"}, "x", %{id: "nope"})
  end

  test "max_staleness_ms: stale before the first sync and after the window", %{new: new, clock: clock} do
    m = new.(max_staleness_ms: 1000)
    assert %{allowed: false, code: :stale} = Mirror.check(m, {:user, "u1"}, "x", %{id: "res_d"})
    m = sync!(m)
    refute match?(%{code: :stale}, Mirror.check(m, {:user, "u1"}, "x", %{id: "res_d"}))
    Agent.update(clock, &(&1 + 5000))
    assert %{code: :stale} = Mirror.check(m, {:user, "u1"}, "x", %{id: "res_d"})
  end

  test "serve_stale_for_ms serves with stale: true", %{new: new, clock: clock} do
    m = sync!(new.(max_staleness_ms: 1000, serve_stale_for_ms: 10_000))
    Agent.update(clock, &(&1 + 5000))
    assert %{stale: true} = Mirror.check(m, {:user, "u1"}, "x", %{id: "res_d"})
  end

  test "tree_refresh_ms skips re-pulling the tree between syncs", %{new: new} do
    {:ok, pulls} = Agent.start_link(fn -> 0 end)

    api = %{
      types: fn -> Agent.update(pulls, &(&1 + 1)); {:ok, %{"data" => []}} end,
      resources: fn _ -> {:ok, %{"data" => [], "has_more" => false}} end,
      changes: fn _ -> {:ok, %{"data" => [], "has_more" => false}} end
    }

    {:ok, store} = MemoryStore.start_link()
    m = Mirror.new(store: {MemoryStore, store}, api: api, tree_refresh_ms: 60_000, now_ms: fn -> @now end)
    m = sync!(m)
    _ = sync!(m)
    assert Agent.get(pulls, & &1) == 1
    _ = new
  end

  test "webhooks apply created and deleted assignments", %{new: new} do
    m = sync!(new.([]))
    data = %{"id" => "a9", "resource_id" => "res_d", "subject" => %{"type" => "user", "id" => "u9"}, "role" => "editor"}
    assert Mirror.apply_webhook(m, %{"type" => "resource_role_assignment.created", "data" => data})
    assert Mirror.can?(m, {:user, "u9"}, "doc:edit", %{id: "res_d"})
    assert Mirror.apply_webhook(m, %{"type" => "resource_role_assignment.deleted", "data" => data})
    refute Mirror.can?(m, {:user, "u9"}, "doc:edit", %{id: "res_d"})
    refute Mirror.apply_webhook(m, %{"type" => "resource_role_assignment.created", "data" => %{"id" => "x"}})
    refute Mirror.apply_webhook(m, %{"type" => "user.created", "data" => %{}})
  end

  test "an ancestor cycle terminates" do
    chain_type = %{key: "t", inherit: true, roles: [%{"key" => "r", "permissions" => ["p"]}]}
    chain = [%{resource_id: "a", type: chain_type, assignments: []}, %{resource_id: "b", type: chain_type, assignments: [%{subject: "user:u", role_key: "r", inherit: true}]}]
    assert [%{resource_id: "b", inherited: true}] = Mirror.resolve_grants(chain, ["user:u"], "p")
  end
end
