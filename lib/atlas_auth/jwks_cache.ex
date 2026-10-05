defmodule AtlasAuth.JWKSCache do
  @moduledoc """
  An in-process JWKS cache, keyed by URL, that refetches on a `kid`-miss at most
  once a minute.

  WHY the rate limit on the refetch is a *security* property and not mere
  politeness: without it, an attacker sends session tokens carrying random `kid`
  values and every single one forces an outbound request to the JWKS endpoint —
  turning any unauthenticated caller into a traffic amplifier aimed at Atlas,
  launched from inside the customer's own infrastructure. The cache's job is as
  much to *refuse* to fetch as it is to fetch.

  WHY a stale cache still serves: a JWKS that is an hour out of date still
  verifies every token signed by a key it already contains. So when a refetch is
  throttled or the endpoint is down, we keep serving the keys we have. The system
  degrades to "a brand-new signing key does not work yet" (and only for the ~60s
  until the throttle opens), never to "nobody can authenticate".

  WHY one GenServer keyed by URL rather than a process per instance: the throttle
  window and the cached key set are shared state that must be consistent across
  all concurrent requests for an instance. Serializing cache reads/writes through
  one process is the simplest correct way to get that, and JWKS reads are rare
  (a cache hit is a single `GenServer.call`, no I/O).

  Time is tracked in milliseconds and the clock (`now_ms`) is passed in on every
  call so a test can drive the throttle with no real sleeping.
  """
  use GenServer

  @typedoc "A JWKS key entry — a string-keyed map as it appears in the JWKS JSON."
  @type jwk :: %{optional(String.t()) => term()}

  @typedoc "A function that fetches the JWKS, returning the list of key entries."
  @type fetcher :: (String.t() -> {:ok, [jwk()]} | {:error, term()})

  @typedoc "The action the last `get/5` took — exposed so a test can assert the throttle bit."
  @type outcome :: :fresh | :cached | :refetched | :throttled | :failed

  # §7.3: at most one refetch per minute, however many kid-misses arrive.
  @refetch_interval_ms 60_000
  # §7.3 serves `Cache-Control: max-age=3600`; honoured rather than ignored.
  @default_ttl_ms 3_600_000

  def refetch_interval_ms, do: @refetch_interval_ms
  def default_ttl_ms, do: @default_ttl_ms

  @doc false
  def start_link(opts) when is_list(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  # Support being listed as a bare child (`AtlasAuth.JWKSCache`) in a supervisor.
  def start_link(), do: start_link([])

  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :name, __MODULE__),
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  @doc """
  Return the JWKS key list to verify `kid` against, fetching through `fetcher`
  only when the cache is empty, expired, or `kid` is genuinely unknown — and even
  then at most once per minute per URL.

  Returns `{keys, outcome}`; `keys` is `nil` only when the cache is empty and the
  first fetch failed (the verifier maps that to `:no_keys`).
  """
  @spec get(GenServer.server(), String.t(), String.t() | nil, fetcher(), integer(), keyword()) ::
          {[jwk()] | nil, outcome()}
  def get(server \\ __MODULE__, url, kid, fetcher, now_ms, opts \\ []) do
    GenServer.call(server, {:get, url, kid, fetcher, now_ms, opts})
  end

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:get, url, kid, fetcher, now_ms, opts}, _from, state) do
    ttl = Keyword.get(opts, :ttl_ms, @default_ttl_ms)
    interval = Keyword.get(opts, :refetch_interval_ms, @refetch_interval_ms)
    entry = Map.get(state, url)

    expired? = entry == nil or now_ms - entry.fetched_at >= ttl
    kid_miss? = entry != nil and not has_kid?(entry.keys, kid)

    cond do
      not expired? and not kid_miss? ->
        {:reply, {entry.keys, :cached}, state}

      # The throttle: a kid-miss inside the window is answered from cache and the
      # token simply fails to verify. This is the line that stops the amplifier.
      kid_miss? and not expired? and now_ms - entry.last_attempt_at < interval ->
        {:reply, {entry.keys, :throttled}, state}

      true ->
        attempt_fetch(url, kid_miss?, fetcher, now_ms, entry, state)
    end
  end

  defp attempt_fetch(url, kid_miss?, fetcher, now_ms, entry, state) do
    case safe_fetch(fetcher, url) do
      {:ok, keys} when is_list(keys) ->
        new_entry = %{keys: keys, fetched_at: now_ms, last_attempt_at: now_ms}
        outcome = if kid_miss?, do: :refetched, else: :fresh
        {:reply, {keys, outcome}, Map.put(state, url, new_entry)}

      _ ->
        # Keep serving whatever we have; only mark the failed attempt so the
        # throttle still applies to the next miss.
        kept = entry && entry.keys

        updated =
          if entry, do: Map.put(state, url, %{entry | last_attempt_at: now_ms}), else: state

        {:reply, {kept, :failed}, updated}
    end
  end

  defp safe_fetch(fetcher, url) do
    fetcher.(url)
  rescue
    _ -> {:error, :fetch_raised}
  catch
    _, _ -> {:error, :fetch_threw}
  end

  defp has_kid?(keys, kid) when is_list(keys) do
    cond do
      kid in [nil, ""] -> keys != []
      true -> Enum.any?(keys, fn k -> is_map(k) and k["kid"] == kid end)
    end
  end

  defp has_kid?(_keys, _kid), do: false
end
