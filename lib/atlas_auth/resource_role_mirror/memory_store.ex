defmodule AtlasAuth.ResourceRoleMirror.MemoryStore do
  @moduledoc "An in-memory `AtlasAuth.ResourceRoleMirror.Store` (an `Agent`), for tests and single-process apps."
  @behaviour AtlasAuth.ResourceRoleMirror.Store
  use Agent

  @doc false
  def start_link(opts \\ []) do
    agent_opts = if opts[:name], do: [name: opts[:name]], else: []
    Agent.start_link(fn -> %{assignments: %{}, resources: %{}, types: %{}, cursor: nil, last_sync_at: nil} end, agent_opts)
  end

  @impl true
  def get_cursor(ref), do: Agent.get(ref, & &1.cursor)
  @impl true
  def set_cursor(ref, c), do: Agent.update(ref, &%{&1 | cursor: c})
  @impl true
  def get_type(ref, key), do: Agent.get(ref, & &1.types[key])

  @impl true
  def get_resource(ref, %{id: id}), do: Agent.get(ref, & &1.resources[id])

  def get_resource(ref, %{type: type, external_id: ext}) do
    Agent.get(ref, fn s -> Enum.find_value(s.resources, fn {_, r} -> r.type == type and r.external_id == ext && r end) end)
  end

  @impl true
  def assignments_on(ref, ids) do
    want = MapSet.new(ids)
    Agent.get(ref, fn s -> s.assignments |> Map.values() |> Enum.filter(&MapSet.member?(want, &1.resource_id)) end)
  end

  @impl true
  def replace_types(ref, types), do: Agent.update(ref, &%{&1 | types: Map.new(types, fn t -> {t.key, t} end)})
  @impl true
  def replace_resources(ref, rs), do: Agent.update(ref, &%{&1 | resources: Map.new(rs, fn r -> {r.id, r} end)})

  @impl true
  def apply_changes(ref, changes) do
    Agent.update(ref, fn s ->
      assignments =
        Enum.reduce(changes, s.assignments, fn
          {:deleted, a}, acc -> Map.delete(acc, a.id)
          {:created, a}, acc -> Map.put(acc, a.id, a)
        end)

      %{s | assignments: assignments}
    end)
  end

  @impl true
  def get_last_sync_at(ref), do: Agent.get(ref, & &1.last_sync_at)
  @impl true
  def set_last_sync_at(ref, at), do: Agent.update(ref, &%{&1 | last_sync_at: at})
end
