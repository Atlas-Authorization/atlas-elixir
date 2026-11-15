defmodule AtlasAuth.KeyMirror.MemoryStore do
  @moduledoc "An in-memory `AtlasAuth.KeyMirror.Store` (an `Agent`), for tests and single-process apps. Back it with a table in production."
  @behaviour AtlasAuth.KeyMirror.Store
  use Agent

  @doc false
  def start_link(opts \\ []) do
    agent_opts = if opts[:name], do: [name: opts[:name]], else: []
    Agent.start_link(fn -> %{keys: %{}, cursor: nil, last_sync_at: nil} end, agent_opts)
  end

  @doc "Every stored key, for assertions."
  def all(ref), do: Agent.get(ref, &Map.values(&1.keys))

  @impl true
  def put(ref, key), do: Agent.update(ref, fn s -> %{s | keys: Map.put(s.keys, key.id, key)} end)

  @impl true
  def get(ref, id), do: Agent.get(ref, & &1.keys[id])

  @impl true
  def get_by_hash(ref, hash), do: Agent.get(ref, fn s -> Enum.find_value(s.keys, fn {_, k} -> k.hash == hash && k end) end)

  @impl true
  def mark_revoked(ref, id, at, reason) do
    Agent.update(ref, fn s ->
      case s.keys[id] do
        %{revoked_at: nil} = k -> %{s | keys: Map.put(s.keys, id, %{k | revoked_at: at, revoked_reason: reason || k.revoked_reason})}
        _ -> s
      end
    end)
  end

  @impl true
  def mark_membership_ended(ref, user_id, org_id, at) do
    Agent.update(ref, fn s ->
      keys =
        Map.new(s.keys, fn
          {id, %{revoked_at: nil, subject_type: "user", subject_id: ^user_id, organization_id: ^org_id} = k} ->
            {id, %{k | revoked_at: at, revoked_reason: "membership_ended"}}

          other ->
            other
        end)

      %{s | keys: keys}
    end)
  end

  @impl true
  def get_cursor(ref), do: Agent.get(ref, & &1.cursor)
  @impl true
  def set_cursor(ref, c), do: Agent.update(ref, &%{&1 | cursor: c})
  @impl true
  def get_last_sync_at(ref), do: Agent.get(ref, & &1.last_sync_at)
  @impl true
  def set_last_sync_at(ref, at), do: Agent.update(ref, &%{&1 | last_sync_at: at})
end
