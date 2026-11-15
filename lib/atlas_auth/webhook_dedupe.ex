defmodule AtlasAuth.WebhookDedupe do
  @moduledoc """
  Verify an Atlas webhook and drop a delivery whose `atlas-id` was already seen.

  Atlas retries a delivery with the same `atlas-id`, so a handler that is not
  idempotent should remember the ids it handled. `verify_and_dedupe/5` checks the
  signature and timestamp exactly like `AtlasAuth.Webhook` and then claims the
  delivery id in a store. An unverified delivery never touches the store.

  A store is a `{module, ref}` pair whose module implements this behaviour.
  `AtlasAuth.WebhookDedupe.MemoryStore` is a single-VM store; back it with Redis or
  a table when you run more than one node.

      {:ok, store} = AtlasAuth.WebhookDedupe.MemoryStore.start_link([])

      case AtlasAuth.WebhookDedupe.verify_and_dedupe(raw_body, conn.req_headers, secret, {AtlasAuth.WebhookDedupe.MemoryStore, store}) do
        {:ok, %{duplicate: true}} -> send_resp(conn, 200, "")
        {:ok, %{event: event, release: release}} ->
          case handle(event) do
            :ok -> send_resp(conn, 200, "")
            _ -> release.(); send_resp(conn, 500, "")
          end
        {:error, _} -> send_resp(conn, 400, "")
      end
  """

  @doc "Atomically remember `key` for `ttl_seconds`. `true` when it was NOT already remembered."
  @callback set_if_absent(ref :: term(), key :: String.t(), ttl_seconds :: pos_integer()) :: boolean()

  @doc "Forget `key`, so a retry of a failed delivery is processed."
  @callback delete(ref :: term(), key :: String.t()) :: :ok

  @type store :: {module(), term()}
  @type result :: %{
          event: map(),
          duplicate: boolean(),
          delivery_id: String.t(),
          release: (-> :ok)
        }

  @doc """
  Verify and dedupe. `headers` is a list of `{name, value}` pairs or a map.

  Options: `:ttl_seconds` (default 86400; keep it longer than your endpoint's retry
  window), `:key_prefix` (default `"atlas-webhook:"`), `:url` (the exact URL Atlas
  POSTed to; also checks `v2` signatures), `:require_v2`, `:now_ms`, `:tolerance_ms`.

  Returns `{:ok, %{event:, duplicate:, delivery_id:, release:}}`, or
  `{:error, reason}` with the `AtlasAuth.Webhook` reasons plus `:invalid_body`.
  """
  @spec verify_and_dedupe(binary(), list() | map(), String.t(), store(), keyword()) ::
          {:ok, result()} | {:error, atom()}
  def verify_and_dedupe(body, headers, secret, {mod, ref}, opts \\ []) do
    verify_opts = Keyword.take(opts, [:now_ms, :tolerance_ms, :require_v2])

    verified =
      case opts[:url] do
        nil -> AtlasAuth.Webhook.verify(body, headers, secret, verify_opts)
        url -> AtlasAuth.Webhook.verify_url(body, headers, secret, url, verify_opts)
      end

    with {:ok, %{event: event, delivery_id: id}} <- verified,
         true <- is_map(event) or {:error, :invalid_body} do
      key = Keyword.get(opts, :key_prefix, "atlas-webhook:") <> id
      fresh = mod.set_if_absent(ref, key, Keyword.get(opts, :ttl_seconds, 86_400))

      release = fn ->
        if function_exported?(mod, :delete, 2), do: mod.delete(ref, key), else: :ok
      end

      {:ok, %{event: event, duplicate: not fresh, delivery_id: id, release: release}}
    end
  end
end

defmodule AtlasAuth.WebhookDedupe.MemoryStore do
  @moduledoc "A single-VM `AtlasAuth.WebhookDedupe` store (an `Agent`). Options: `:name`, `:now_ms` (zero-arity clock)."
  @behaviour AtlasAuth.WebhookDedupe
  use Agent

  @doc false
  def start_link(opts \\ []) do
    now = Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end)
    agent_opts = if opts[:name], do: [name: opts[:name]], else: []
    Agent.start_link(fn -> %{now: now, seen: %{}} end, agent_opts)
  end

  @impl true
  def set_if_absent(ref, key, ttl_seconds) do
    Agent.get_and_update(ref, fn %{now: now, seen: seen} = s ->
      t = now.()
      live = Map.reject(seen, fn {_k, exp} -> exp <= t end)

      if Map.has_key?(live, key),
        do: {false, %{s | seen: live}},
        else: {true, %{s | seen: Map.put(live, key, t + ttl_seconds * 1000)}}
    end)
  end

  @impl true
  def delete(ref, key) do
    Agent.update(ref, fn s -> %{s | seen: Map.delete(s.seen, key)} end)
  end
end
