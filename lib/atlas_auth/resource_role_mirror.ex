defmodule AtlasAuth.ResourceRoleMirror.Store do
  @moduledoc """
  What `AtlasAuth.ResourceRoleMirror` needs from storage. A store is a `{module, ref}` pair;
  every callback receives `ref` first.

  Shapes: a type is `%{key:, inherit:, roles: [role]}` where a role is the API's map
  (`"key"`, `"permissions"`, `"includes"`); a resource is `%{id:, type:, external_id:, parent_id:}`;
  an assignment is `%{id:, resource_id:, subject:, role:, inherit:}` with `subject` as `"user:usr_1"`.
  A resource reference is `%{id: id}` or `%{type: type, external_id: external_id}`.
  """
  @callback get_cursor(ref :: term()) :: String.t() | nil
  @callback set_cursor(ref :: term(), String.t()) :: :ok
  @callback get_type(ref :: term(), key :: String.t()) :: map() | nil
  @callback get_resource(ref :: term(), resource_ref :: map()) :: map() | nil
  @doc "Every assignment sitting on any of these resource ids."
  @callback assignments_on(ref :: term(), [String.t()]) :: [map()]
  @doc "Replace the whole type registry."
  @callback replace_types(ref :: term(), [map()]) :: :ok
  @doc "Replace the whole resource tree."
  @callback replace_resources(ref :: term(), [map()]) :: :ok
  @doc "`:created` upserts by assignment id; `:deleted` removes it."
  @callback apply_changes(ref :: term(), [{:created | :deleted, map()}]) :: :ok
  @callback get_last_sync_at(ref :: term()) :: integer() | nil
  @callback set_last_sync_at(ref :: term(), integer()) :: :ok
end

defmodule AtlasAuth.ResourceRoleMirror do
  @moduledoc """
  A local mirror of resource-scoped role assignments, so `can?/4` is answered with no
  network call and with the SAME inheritance rules as `POST /v1/resource_checks`.

  It keeps the resource types (roles, `includes`, `inherit`), the resource tree and the role
  assignments. `sync/1` pulls the types and the tree, then consumes the assignment change feed
  from the stored cursor. `apply_webhook/2` applies `resource_role_assignment.created` / `.deleted`
  events between syncs.

  One difference from the server: Atlas adds the user's organizations and groups to the subject
  itself. Offline you pass them: `can?(mirror, {:user, id}, permission, resource, orgs: [...], groups: [...])`.

      mirror = AtlasAuth.ResourceRoleMirror.new(client: client, store: {AtlasAuth.ResourceRoleMirror.MemoryStore, pid})
      {:ok, _} = AtlasAuth.ResourceRoleMirror.sync(mirror)
      AtlasAuth.ResourceRoleMirror.can?(mirror, {:user, "usr_1"}, "doc:edit", %{type: "doc", external_id: "d1"})

  Options for `new/1`: `:store` (required); `:client` (an `Atlas.Client`) or `:api` (a map of
  `:types` (zero-arity), `:resources` (params keyword) and `:changes` (params keyword) functions, each
  returning `{:ok, page}` | `{:error, term}`); `:max_staleness_ms`, `:serve_stale_for_ms`,
  `:on_serve_stale` (as for `AtlasAuth.KeyMirror`); `:tree_refresh_ms` (re-pull types and tree on a sync
  only when this long has passed; default 0 = every sync); `:now_ms` (zero-arity clock).
  """

  defstruct [:store, :api, :now, opts: [], tree_at: nil]

  @type t :: %__MODULE__{}

  # Same cap as the server's ancestor walk.
  @max_depth 16

  @doc "Build a mirror."
  @spec new(keyword()) :: t()
  def new(opts) do
    api =
      cond do
        is_map(opts[:api]) ->
          opts[:api]

        client = opts[:client] ->
          %{
            types: fn -> Atlas.ResourceTypes.list(client) end,
            resources: fn params -> Atlas.Resources.list(client, params: params) end,
            changes: fn params -> Atlas.ResourceRoleAssignments.get_changes(client, params: params) end
          }

        true ->
          raise ArgumentError, "AtlasAuth.ResourceRoleMirror needs :client or :api"
      end

    %__MODULE__{
      store: Keyword.fetch!(opts, :store),
      api: api,
      now: Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end),
      opts: opts
    }
  end

  @doc "Epoch ms of the last completed `sync/1`, or nil."
  @spec last_sync_at(t()) :: integer() | nil
  def last_sync_at(m), do: call(m, :get_last_sync_at, [])

  @doc """
  The verdict and the grants behind it, in the shape of `POST /v1/resource_checks`:
  `%{allowed:, resource_id:, grants: [%{resource_id:, role:, subject:, inherited:}], code:, stale:}`.
  `code` is `:unknown_resource` or `:stale`.
  """
  @spec check(t(), {atom() | String.t(), String.t()}, String.t(), map(), keyword()) :: map()
  def check(%__MODULE__{} = m, {type, id}, permission, resource, opts \\ []) do
    case freshness(m) do
      {:error, _} ->
        %{allowed: false, resource_id: nil, grants: [], code: :stale}

      {:ok, stale?} ->
        row = call(m, :get_resource, [resource])

        cond do
          row == nil ->
            %{allowed: false, resource_id: nil, grants: [], code: :unknown_resource}

          not is_binary(permission) or permission == "" ->
            %{allowed: false, resource_id: row.id, grants: []}

          true ->
            subjects =
              MapSet.new(
                ["#{type}:#{id}"] ++ Enum.map(opts[:groups] || [], &"group:#{&1}") ++ Enum.map(opts[:orgs] || [], &"org:#{&1}")
              )

            grants = resolve_grants(chain_of(m, row), subjects, permission)

            base = %{
              allowed: grants != [],
              resource_id: row.id,
              grants: Enum.map(grants, &%{resource_id: &1.resource_id, role: &1.role, subject: &1.subject, inherited: &1.inherited})
            }

            if stale?, do: Map.put(base, :stale, true), else: base
        end
    end
  end

  @doc "May `subject` hold `permission` on `resource`? Answered locally."
  @spec can?(t(), {atom() | String.t(), String.t()}, String.t(), map(), keyword()) :: boolean()
  def can?(m, subject, permission, resource, opts \\ []), do: check(m, subject, permission, resource, opts).allowed

  defp freshness(%{opts: opts} = m) do
    case opts[:max_staleness_ms] do
      nil ->
        {:ok, false}

      max ->
        at = last_sync_at(m)
        behind = if at == nil, do: :infinity, else: m.now.() - at - max

        cond do
          behind != :infinity and behind <= 0 -> {:ok, false}
          at == nil or behind > Keyword.get(opts, :serve_stale_for_ms, 0) -> {:error, :stale}
          true ->
            if cb = opts[:on_serve_stale], do: cb.(%{last_sync_at: at, stale_for_ms: behind})
            {:ok, true}
        end
    end
  end

  # The resource, then its ancestors (cycle-safe, depth-capped), exactly like the server: the
  # ancestors dedupe among themselves only, so a cycle yields the start resource once more.
  defp chain_of(m, resource) do
    ancestors = walk_up(m, resource.parent_id, [], 0)
    rows = [resource | ancestors]
    assignments = call(m, :assignments_on, [Enum.map(rows, & &1.id)])

    Enum.map(rows, fn r ->
      t = call(m, :get_type, [r.type])

      %{
        resource_id: r.id,
        type: %{key: r.type, inherit: if(t, do: t.inherit, else: true), roles: if(t, do: t.roles, else: [])},
        assignments:
          for a <- assignments, a.resource_id == r.id do
            %{subject: a.subject, role_key: a.role, inherit: a.inherit}
          end
      }
    end)
  end

  defp walk_up(_m, nil, acc, _i), do: Enum.reverse(acc)
  defp walk_up(_m, _id, acc, i) when i >= @max_depth, do: Enum.reverse(acc)

  defp walk_up(m, id, acc, i) do
    row = call(m, :get_resource, [%{id: id}])

    if row == nil or Enum.any?(acc, &(&1.id == row.id)),
      do: Enum.reverse(acc),
      else: walk_up(m, row.parent_id, [row | acc], i + 1)
  end

  @doc """
  The server's grant resolver over a chain of `%{resource_id:, type:, assignments: [%{subject:, role_key:, inherit:}]}`
  (resource first). Returns `[%{resource_id:, role:, subject:, inherited:}]`.
  """
  @spec resolve_grants([map()], Enumerable.t(), String.t()) :: [map()]
  def resolve_grants(chain, subjects, permission) do
    held = MapSet.new(subjects)

    chain
    |> Enum.with_index()
    |> Enum.reduce_while([], fn {link, i}, acc ->
      found =
        for a <- link.assignments,
            MapSet.member?(held, a.subject),
            i == 0 or a.inherit,
            perms = role_permissions(link.type, a.role_key, MapSet.new()),
            MapSet.member?(perms, permission) or MapSet.member?(perms, "*") do
          %{resource_id: link.resource_id, role: a.role_key, subject: a.subject, inherited: i > 0}
        end

      acc = acc ++ found
      # The next link up is only reachable when this resource's type inherits.
      if link.type.inherit, do: {:cont, acc}, else: {:halt, acc}
    end)
  end

  # All permissions a role grants, following `includes` (cycle-safe). `*` means every permission.
  defp role_permissions(type, role_key, seen) do
    if MapSet.member?(seen, role_key) do
      MapSet.new()
    else
      seen = MapSet.put(seen, role_key)

      case Enum.find(type.roles, &(&1["key"] == role_key)) do
        nil ->
          MapSet.new()

        role ->
          base = MapSet.new(role["permissions"] || [])

          Enum.reduce(role["includes"] || [], base, fn inc, acc ->
            MapSet.union(acc, role_permissions(type, inc, seen))
          end)
      end
    end
  end

  @doc """
  Pull the types and the resource tree (when `:tree_refresh_ms` has passed), then consume the
  assignment change feed from the stored cursor. Call it on a timer and at startup.
  Returns `{:ok, mirror, %{applied: n}}` (the mirror records when the tree was last pulled) or `{:error, term}`.
  """
  @spec sync(t()) :: {:ok, t(), %{applied: non_neg_integer()}} | {:error, term()}
  def sync(%__MODULE__{} = m) do
    with {:ok, m} <- maybe_pull_tree(m),
         {:ok, applied} <- pull_changes(m, call(m, :get_cursor, []), 0) do
      call(m, :set_last_sync_at, [m.now.()])
      {:ok, m, %{applied: applied}}
    end
  end

  defp maybe_pull_tree(m) do
    refresh = Keyword.get(m.opts, :tree_refresh_ms, 0)

    if m.tree_at == nil or m.now.() - m.tree_at >= refresh do
      # Tree first: an assignment the feed then delivers never names a resource this mirror lacks.
      with {:ok, %{"data" => types}} <- m.api.types.(),
           {:ok, tree} <- pull_resources(m, nil, []) do
        call(m, :replace_types, [Enum.map(types, &%{key: &1["key"], inherit: &1["inherit"], roles: &1["roles"] || []})])
        call(m, :replace_resources, [tree])
        {:ok, %{m | tree_at: m.now.()}}
      else
        {:error, e} -> {:error, e}
        other -> {:error, {:unexpected, other}}
      end
    else
      {:ok, m}
    end
  end

  defp pull_resources(m, cursor, acc) do
    params = [limit: 1000] ++ if(cursor, do: [starting_after: cursor], else: [])

    with {:ok, page} <- m.api.resources.(params) do
      acc =
        acc ++
          Enum.map(page["data"] || [], &%{id: &1["id"], type: &1["type"], external_id: &1["external_id"], parent_id: &1["parent_id"]})

      if page["has_more"] == true and is_binary(page["next_cursor"]),
        do: pull_resources(m, page["next_cursor"], acc),
        else: {:ok, acc}
    end
  end

  defp pull_changes(m, after_cursor, applied) do
    params = [limit: 500] ++ if(after_cursor, do: [after: after_cursor], else: [])

    with {:ok, page} <- m.api.changes.(params) do
      data = page["data"] || []

      changes =
        Enum.map(data, fn c ->
          kind = if c["change"] == "deleted", do: :deleted, else: :created

          {kind,
           %{
             id: c["assignment_id"],
             resource_id: c["resource_id"],
             subject: "#{get_in(c, ["subject", "type"])}:#{get_in(c, ["subject", "id"])}",
             role: c["role"],
             inherit: c["inherit"]
           }}
        end)

      call(m, :apply_changes, [changes])
      next = page["next_cursor"]
      if is_binary(next), do: call(m, :set_cursor, [next])
      applied = applied + length(data)

      if page["has_more"] == true and is_binary(next),
        do: pull_changes(m, next, applied),
        else: {:ok, applied}
    end
  end

  @doc """
  Apply a VERIFIED `resource_role_assignment.created` / `.deleted` webhook event map
  (`%{"type" => ..., "data" => ...}`). Returns whether the event changed the mirror.
  """
  @spec apply_webhook(t(), map()) :: boolean()
  def apply_webhook(%__MODULE__{} = m, %{"type" => type, "data" => %{} = d})
      when type in ["resource_role_assignment.created", "resource_role_assignment.deleted"] do
    with id when is_binary(id) <- d["id"],
         rid when is_binary(rid) <- d["resource_id"],
         role when is_binary(role) <- d["role"],
         st when is_binary(st) <- get_in(d, ["subject", "type"]),
         sid when is_binary(sid) <- get_in(d, ["subject", "id"]) do
      kind = if type == "resource_role_assignment.created", do: :created, else: :deleted
      call(m, :apply_changes, [[{kind, %{id: id, resource_id: rid, subject: "#{st}:#{sid}", role: role, inherit: d["inherit"] != false}}]])
      true
    else
      _ -> false
    end
  end

  def apply_webhook(_m, _event), do: false

  defp call(%__MODULE__{store: {mod, ref}}, fun, args), do: apply(mod, fun, [ref | args])
end
