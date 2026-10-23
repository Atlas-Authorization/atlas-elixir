defmodule AtlasAuth.Introspection do
  @moduledoc """
  RFC 7662 token introspection at Atlas, for opaque (reference) access tokens.

  An API, client or instance set to the `opaque` access-token format gets
  `oat_…` tokens only Atlas can read. `introspect/2` asks Atlas's introspection
  endpoint with your API's own client credentials (`client_secret_basic`) and
  caches the answer in a node-local ETS table keyed by the token's SHA-256 (the
  token itself is never kept). The client must be a confidential client the API
  lists in `introspection_client_ids` (or the client the tokens are issued to).

  Pass the options as `introspection:` to `AtlasAuth.AccessToken.verify/2`:

    * `:client_id`, `:client_secret` — required.
    * `:endpoint` — default `<issuer>/oauth2/introspect`.
    * `:cache_ttl_ms` — how long an active answer is reused (default 60 000;
      never past the token's `exp`).
    * `:negative_cache_ttl_ms` — how long an inactive answer is reused
      (default 10 000; 0 disables).
    * `:cache_max` — most answers kept (default 10 000).
    * `:introspect_jwts` — also send JWT access tokens to Atlas, so a revoked
      grant or a banned user is refused before the token expires.
    * `:poster` — `(url, headers, body -> {:ok, status, body} | {:error, term})`;
      the default posts with `:httpc`.
  """
  use GenServer

  @table :atlas_auth_introspection

  def start_link(_ \\ []), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl GenServer
  def init(nil) do
    :ets.new(@table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    {:ok, nil}
  end

  @doc "The cache key for a token: base64url(SHA-256(token))."
  def cache_key(token), do: Base.url_encode64(:crypto.hash(:sha256, token), padding: false)

  @doc """
  The claims of an active access token (`{:ok, map}`), `{:ok, nil}` for an
  inactive one (also for a refresh token), or `{:error, reason}` when Atlas
  could not be asked. `issuer` is the instance issuer; `opts` as above plus
  `:now_ms`.
  """
  @spec introspect(String.t(), String.t(), keyword()) :: {:ok, map() | nil} | {:error, term()}
  def introspect(token, issuer, opts) do
    client_id = opts[:client_id]
    client_secret = opts[:client_secret]

    if client_id in [nil, ""] or client_secret in [nil, ""] do
      {:error, :missing_client_credentials}
    else
      key = {cache_scope(issuer, client_id), cache_key(token)}
      now = Keyword.get(opts, :now_ms, System.system_time(:millisecond))

      case :ets.lookup(@table, key) do
        [{^key, claims, until}] when until > now -> {:ok, claims}
        _ -> ask(token, key, issuer, client_id, client_secret, opts)
      end
    end
  end

  defp cache_scope(issuer, client_id), do: String.trim_trailing(issuer, "/") <> "|" <> client_id

  defp ask(token, key, issuer, client_id, client_secret, opts) do
    endpoint = opts[:endpoint] || String.trim_trailing(issuer, "/") <> "/oauth2/introspect"
    basic = "Basic " <> Base.encode64(form(client_id) <> ":" <> form(client_secret))

    headers = [
      {"authorization", basic},
      {"accept", "application/json"},
      {"content-type", "application/x-www-form-urlencoded"}
    ]

    body = "token=" <> form(token) <> "&token_type_hint=access_token"
    poster = Keyword.get(opts, :poster, &default_post/3)

    with {:ok, status, raw} when status in 200..299 <- poster.(endpoint, headers, body),
         {:ok, decoded} <- Jason.decode(raw) do
      claims =
        if is_map(decoded) and decoded["active"] == true and
             decoded["token_use"] != "refresh_token",
           do: decoded,
           else: nil

      remember(key, claims, opts)
      {:ok, claims}
    else
      {:ok, status, _raw} -> {:error, {:http_status, status}}
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_json}
      {:error, reason} -> {:error, reason}
    end
  end

  defp remember(key, claims, opts) do
    now = Keyword.get(opts, :now_ms, System.system_time(:millisecond))

    ttl =
      if claims,
        do: Keyword.get(opts, :cache_ttl_ms, 60_000),
        else: Keyword.get(opts, :negative_cache_ttl_ms, 10_000)

    until = now + ttl

    until =
      case claims && claims["exp"] do
        exp when is_number(exp) -> min(until, trunc(exp * 1000))
        _ -> until
      end

    if until > now do
      :ets.insert(@table, {key, claims, until})
      max = Keyword.get(opts, :cache_max, 10_000)

      if :ets.info(@table, :size) > max do
        :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
        trim(max)
      end
    end

    :ok
  end

  # Over the cap with nothing expired: drop the entries that expire soonest.
  defp trim(max) do
    size = :ets.info(@table, :size)

    if size > max do
      :ets.tab2list(@table)
      |> Enum.sort_by(fn {_k, _c, until} -> until end)
      |> Enum.take(size - max)
      |> Enum.each(fn {k, _c, _u} -> :ets.delete(@table, k) end)
    end
  end

  @doc false
  def clear, do: :ets.delete_all_objects(@table)

  @doc false
  def size, do: :ets.info(@table, :size)

  defp form(value), do: URI.encode_www_form(value)

  @doc false
  def default_post(url, headers, body) do
    _ = :inets.start()
    _ = :ssl.start()

    {content_type, rest} =
      List.keytake(headers, "content-type", 0) |> then(fn {{_, ct}, rest} -> {ct, rest} end)

    hs = Enum.map(rest, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)
    request = {String.to_charlist(url), hs, String.to_charlist(content_type), body}
    http_opts = [{:timeout, 10_000}, {:connect_timeout, 5_000}]

    case :httpc.request(:post, request, http_opts, [{:body_format, :binary}]) do
      {:ok, {{_v, status, _r}, _h, resp}} -> {:ok, status, resp}
      {:error, reason} -> {:error, reason}
    end
  end
end
