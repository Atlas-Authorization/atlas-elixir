defmodule AtlasAuth.SidRevocation do
  @moduledoc """
  A local list of revoked Atlas session ids, so a verifier that checks tokens
  locally can still refuse a token whose session Atlas has revoked.

  The process polls `GET /v1/sessions/revoked` (a secret key with `sessions:read`)
  at most every `:interval_ms` and keeps each revoked `sid` until a token carrying it
  cannot be live any more (`:max_token_lifetime_seconds`). The worst-case window
  between a revoke and a refusal is the poll interval plus the token lifetime.

      {:ok, list} = AtlasAuth.SidRevocation.start_link(client: Atlas.new(secret_key))

      with {:ok, claims} <- AtlasAuth.Verifier.verify(token, opts),
           :ok <- AtlasAuth.SidRevocation.check(list, claims.sid) do
        {:ok, claims}
      end

  Options: `:client` (an `Atlas.Client`) or `:fetch_page` (a function taking the query
  params as a keyword list and returning `{:ok, page}` | `{:error, term}`); `:interval_ms`
  (default 15000); `:max_token_lifetime_seconds` (3600); `:on_stale` (`:allow`, default,
  keeps trusting the last list when Atlas is unreachable; `:reject` fails closed with
  `{:error, :revocation_unavailable}`); `:stale_after_ms` (120000); `:serve_stale_for_ms`
  (0; with `:reject`, keep answering from the last list this much longer);
  `:on_serve_stale` and `:on_error` callbacks; `:now_ms` (zero-arity clock); `:name`.

  ## Signed status list

  With `source: :status_list` the process fetches the signed list
  (`GET /v1/sessions/revocations/status-list`, also `sessions:read`) and verifies it against the instance
  JWKS with `AtlasAuth.StatusList` (RS256, PS256, ES256, ES384 or EdDSA): a smaller answer than the feed for
  a busy verifier. It needs `:jwks_url` (and `:issuer`, strongly recommended); `:fetch_status_list` (a function
  taking the query params and returning `{:ok, %{"token" => jwt}}`) replaces the default call, and
  `:window_seconds` sets how far back the list reaches. A list that is missing, does not verify, or was cut
  short (`truncated`) cannot clear a session, so the paged feed answers instead (fail closed on a bad
  signature: such a list is never used).
  """
  use GenServer

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name_opt(opts))

  defp name_opt(opts), do: if(opts[:name], do: [name: opts[:name]], else: [])

  @doc "Whether `sid` is currently listed as revoked (polls first when a poll is due)."
  @spec revoked?(GenServer.server(), String.t()) :: boolean()
  def revoked?(server, sid), do: GenServer.call(server, {:revoked?, sid}, 60_000)

  @doc """
  `:ok`, `{:error, :revoked}`, or (with `on_stale: :reject`) `{:error, :revocation_unavailable}`
  when the list could not be refreshed for too long. A nil `sid` passes.
  """
  @spec check(GenServer.server(), String.t() | nil) :: :ok | {:error, :revoked | :revocation_unavailable}
  def check(_server, nil), do: :ok
  def check(server, sid), do: GenServer.call(server, {:check, sid}, 60_000)

  @impl true
  def init(opts) do
    now = Keyword.get(opts, :now_ms, fn -> System.system_time(:millisecond) end)

    fetch =
      cond do
        is_function(opts[:fetch_page], 1) ->
          opts[:fetch_page]

        client = opts[:client] ->
          fn params -> Atlas.Sessions.get_revoked(client, params: params) end

        true ->
          raise ArgumentError, "AtlasAuth.SidRevocation needs :client or :fetch_page"
      end

    {:ok,
     %{
       opts: opts,
       now: now,
       fetch: fetch,
       interval: Keyword.get(opts, :interval_ms, 15_000),
       lifetime_ms: Keyword.get(opts, :max_token_lifetime_seconds, 3600) * 1000,
       revoked: %{},
       status_list: nil,
       status_list_at: nil,
       status_next_at: 0,
       since: nil,
       next_poll_at: 0,
       last_success_at: nil,
       created_at: now.()
     }}
  end

  @impl true
  def handle_call({:revoked?, sid}, _from, state) do
    {verdict, state} = answer(state, sid)
    {:reply, verdict == :revoked, state}
  end

  def handle_call({:check, sid}, _from, state) do
    {verdict, state} = answer(state, sid)

    reply =
      case verdict do
        :revoked -> {:error, :revoked}
        :unavailable -> {:error, :revocation_unavailable}
        :ok -> :ok
      end

    {:reply, reply, state}
  end

  # `:revoked | :ok | :unavailable`: the signed list first when configured, the paged feed otherwise or as the fallback.
  defp answer(state, sid) do
    case state.opts[:source] do
      :status_list ->
        state = refresh_status_list(state)

        case state.status_list do
          %AtlasAuth.StatusList{} = list ->
            cond do
              AtlasAuth.StatusList.has?(list, sid) -> {:revoked, state}
              list.truncated -> feed_answer(state, sid)
              unavailable?(%{state | last_success_at: state.status_list_at}) -> {:unavailable, state}
              true -> {:ok, state}
            end

          nil ->
            feed_answer(state, sid)
        end

      _ ->
        feed_answer(state, sid)
    end
  end

  defp feed_answer(state, sid) do
    state = maybe_poll(state)

    cond do
      listed?(state, sid) -> {:revoked, state}
      unavailable?(state) -> {:unavailable, state}
      true -> {:ok, state}
    end
  end

  defp refresh_status_list(state) do
    now = state.now.()

    if now >= state.status_next_at, do: fetch_status_list(%{state | status_next_at: now + state.interval}, now), else: state
  end

  defp fetch_status_list(state, now) do
    params = if w = state.opts[:window_seconds], do: [window_seconds: w], else: []

    fetch =
      state.opts[:fetch_status_list] ||
        fn p -> Atlas.Sessions.get_revocations_status_list(state.opts[:client], params: p) end

    vopts = [jwks_url: state.opts[:jwks_url], issuer: state.opts[:issuer], now_ms: now] ++ Keyword.take(state.opts, [:fetcher, :cache])

    with {:ok, %{"token" => token}} when is_binary(token) <- safe_fetch(fetch, params),
         {:ok, list} <- AtlasAuth.StatusList.verify(token, vopts) do
      %{state | status_list: list, status_list_at: now}
    else
      error ->
        if cb = state.opts[:on_error], do: cb.(error)
        # The last verified list (if any) stays in force until stale; the next try is one interval away.
        state
    end
  end

  defp listed?(state, sid) do
    case Map.get(state.revoked, sid) do
      nil -> false
      expiry -> expiry > state.now.()
    end
  end

  defp unavailable?(%{opts: opts} = state) do
    if opts[:on_stale] != :reject do
      false
    else
      stale =
        state.now.() - (state.last_success_at || state.created_at) - Keyword.get(opts, :stale_after_ms, 120_000)

      cond do
        stale <= 0 ->
          false

        # A list fetched at least once may be served a little longer; one never fetched may not.
        state.last_success_at != nil and stale <= Keyword.get(opts, :serve_stale_for_ms, 0) ->
          if cb = opts[:on_serve_stale], do: cb.(%{last_success_at: state.last_success_at, stale_for_ms: stale})
          false

        true ->
          true
      end
    end
  end

  defp maybe_poll(state) do
    if state.now.() >= state.next_poll_at, do: poll(state), else: state
  end

  defp poll(state) do
    started = state.now.()
    state = %{state | next_poll_at: started + state.interval}
    since = state.since || started - state.lifetime_ms

    case fetch_all(state, since, nil, state.revoked, started) do
      {:ok, revoked, server_time} ->
        live = Map.reject(revoked, fn {_sid, exp} -> exp <= started end)
        # Re-ask from a little before the answer's own clock, so a row committed late is not missed.
        %{state | revoked: live, since: server_time - 10_000, last_success_at: started}

      {:error, error} ->
        if cb = state.opts[:on_error], do: cb.(error)
        state
    end
  end

  defp fetch_all(state, since, cursor, revoked, started) do
    params = [since: since, limit: 5000] ++ if(cursor, do: [cursor: cursor], else: [])

    case safe_fetch(state.fetch, params) do
      {:ok, page} when is_map(page) ->
        revoked =
          Enum.reduce(page["data"] || [], revoked, fn
            %{"sid" => sid, "revoked_at" => at}, acc when is_binary(sid) and is_integer(at) ->
              Map.put(acc, sid, at + state.lifetime_ms)

            _, acc ->
              acc
          end)

        server_time = page["server_time"] || started

        if page["has_more"] == true and is_binary(page["next_cursor"]),
          do: fetch_all(state, since, page["next_cursor"], revoked, started),
          else: {:ok, revoked, server_time}

      {:error, error} ->
        {:error, error}

      other ->
        {:error, {:unexpected, other}}
    end
  end

  defp safe_fetch(fun, params) do
    fun.(params)
  rescue
    e -> {:error, e}
  end
end
