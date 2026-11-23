defmodule Atlas.Client do
  @moduledoc """
  The HTTP core behind every `Atlas.<Resource>` module (built on `Req`).

  Options for `new/2`: `:base_url` (default `https://api.atlasauth.net`),
  `:req_options` (merged into every `Req` request, for example `plug: {Req.Test, MyStub}`
  in tests) and `:resilience`, a keyword list:

    * `:max_retries` - default 2 (0 when `req_options` has `retry: false`).
    * `:base_delay_ms` (250) and `:max_delay_ms` (30_000) - exponential backoff with jitter.
    * `:jitter` - default `true`.
    * `:status_aware` - default `false`; when `true`, a degraded or partially down Atlas stretches the backoff 2x, a
      `major_outage` (top level or the `backend_api` component) 4x (`status/1`, cached 30 seconds).
    * `:sleep` - `(ms -> any)`, for tests.

  A `429` is retried for every method (it was not processed), honouring `Retry-After` (seconds or an HTTP
  date; a wait longer than `:max_delay_ms` is not waited out and the error carries
  `retry_after_ms`). `500`, `502`, `503` and `504` are retried only for
  `GET`, `HEAD`, `PUT`, `DELETE` and calls with an `:idempotency_key`; a write without one is never retried.

  A connection reset before any response (an idle pooled connection the server closed: `:closed`, `:econnreset`,
  `:epipe`, `:econnrefused`) is retried once, after a short jittered wait, for the same calls. A timeout is never retried.

  Every call emits `:telemetry` events (see `AtlasAuth.Telemetry`) when `:telemetry` is installed.
  """

  defstruct [:secret_key, :base_url, req_options: [], resilience: %{}]

  @type t :: %__MODULE__{}
  @default_base "https://api.atlasauth.net"

  @doc "Build a client from a secret key (`sk_...`)."
  @spec new(String.t(), keyword()) :: t()
  def new(secret_key, opts \\ []) when is_binary(secret_key) and secret_key != "" do
    %__MODULE__{
      secret_key: secret_key,
      base_url: String.trim_trailing(Keyword.get(opts, :base_url, @default_base), "/"),
      req_options: Keyword.get(opts, :req_options, []),
      resilience: opts |> Keyword.get(:resilience, []) |> Map.new()
    }
  end

  @doc false
  @spec request(t(), atom(), String.t(), map(), term(), keyword()) :: {:ok, term()} | {:error, Atlas.Error.t()}
  def request(%__MODULE__{} = c, method, template, bindings, body, opts) do
    meta = %{method: method |> to_string() |> String.upcase(), route: template, base_url: c.base_url}

    AtlasAuth.Telemetry.span([:atlas, :request], meta, fn ->
      result = run(c, method, template, expand(template, bindings), body, opts, 0)

      stop =
        case result do
          {:ok, _} -> %{status: :ok}
          {:error, %Atlas.Error{} = e} -> %{status: :error, http_status: e.status, code: e.code, request_id: e.request_id}
        end

      {result, Map.merge(meta, stop)}
    end)
  end

  @doc false
  # One raw call for diagnostics: `{:ok, %Req.Response{}}` for any HTTP status, `{:error, %Atlas.Error{}}` on transport failure.
  def raw(%__MODULE__{} = c, method, path, opts \\ []) do
    case Req.request(build(c, method, path, nil, opts) |> Keyword.put(:retry, false)) do
      {:ok, %Req.Response{} = r} -> {:ok, r}
      {:error, reason} -> {:error, Atlas.Error.transport(reason)}
    end
  end

  defp run(c, method, template, path, body, opts, attempt) do
    result =
      case send_once(c, method, build(c, method, path, body, opts), opts) do
        {:ok, %Req.Response{status: s} = r} when s in 200..299 -> {:ok, decode(r)}
        {:ok, %Req.Response{status: s} = r} -> {:error, Atlas.Error.from_response(s, decode(r), r.headers)}
        {:error, reason} -> {:error, Atlas.Error.transport(reason)}
      end

    cfg = resilience(c)

    with {:error, %Atlas.Error{} = e} <- result,
         true <- attempt < cfg.max_retries,
         true <- retryable?(e, method, opts),
         {:ok, delay} <- delay_ms(c, cfg, e, attempt) do
      AtlasAuth.Telemetry.execute([:atlas, :request, :retry], %{delay_ms: delay, attempt: attempt + 1}, %{
        method: method |> to_string() |> String.upcase(),
        route: template,
        http_status: e.status,
        code: e.code
      })

      cfg.sleep.(delay)
      run(c, method, template, path, body, opts, attempt + 1)
    else
      _ -> result
    end
  end

  # One request; a connection reset before any response (a pooled connection the server closed while idle) is
  # retried once, for calls that are safe to repeat. Never a timeout.
  defp send_once(c, method, req, opts) do
    case Req.request(req) do
      {:error, %{reason: reason}} = first when reason in [:closed, :econnreset, :epipe, :econnrefused] ->
        if replayable?(method, opts) do
          resilience(c).sleep.(25 + :rand.uniform(100))
          Req.request(req)
        else
          first
        end

      other ->
        other
    end
  end

  defp replayable?(method, opts), do: method in [:get, :head, :put, :delete] or opts[:idempotency_key] not in [nil, ""]

  defp build(c, method, path, body, opts) do
    headers =
      [{"authorization", "Bearer " <> c.secret_key}, {"accept", "application/json"}] ++
        idem(opts[:idempotency_key]) ++ Enum.map(opts[:headers] || [], fn {k, v} -> {to_string(k), to_string(v)} end)

    Keyword.merge(
      # Retries are decided here (status aware, `Retry-After` honoured); Req's own retry stays off unless a caller turns it on.
      [method: method, url: c.base_url <> path, headers: headers, decode_body: false, params: opts[:params] || [], retry: false],
      c.req_options
    )
    |> put_body(body, opts[:content_type])
  end

  # 429 is retried for every method (the request was refused, not processed). 500, 502, 503, 504 only when repeating
  # the call is safe: GET, HEAD, PUT, DELETE, or a call with an idempotency key. Transport failures: see send_once/4.
  defp retryable?(%Atlas.Error{status: 429}, _method, _opts), do: true

  defp retryable?(%Atlas.Error{status: s}, method, opts) when s in [500, 502, 503, 504],
    do: replayable?(method, opts)

  defp retryable?(_, _, _), do: false

  @doc false
  def resilience(%__MODULE__{} = c) do
    explicit = c.resilience || %{}
    off? = Keyword.get(c.req_options, :retry) == false and not Map.has_key?(explicit, :max_retries)

    Map.merge(
      %{max_retries: if(off?, do: 0, else: 2), base_delay_ms: 250, max_delay_ms: 30_000, jitter: true, status_aware: false, sleep: &Process.sleep/1},
      explicit
    )
  end

  # `{:ok, ms}` to wait, or `:give_up` when the server asked for longer than `max_delay_ms`.
  defp delay_ms(c, cfg, %Atlas.Error{retry_after_ms: ra}, _attempt) when is_integer(ra) do
    if ra > cfg.max_delay_ms, do: :give_up, else: {:ok, max(ra, 0) |> then(&if(cfg.status_aware, do: status_stretch(c, &1, cfg), else: &1))}
  end

  defp delay_ms(c, cfg, %Atlas.Error{}, attempt) do
    exp = min(cfg.base_delay_ms * Integer.pow(2, attempt), cfg.max_delay_ms)
    exp = if cfg.jitter, do: div(exp, 2) + :rand.uniform(max(div(exp, 2), 1)), else: exp
    {:ok, if(cfg.status_aware, do: status_stretch(c, exp, cfg), else: exp)}
  end

  # With `status_aware: true`, a degraded or down Atlas (read from `GET /v1/status`, cached 30 s) stretches the wait 2x / 4x.
  defp status_stretch(c, ms, cfg) do
    factor =
      case service_status(c) do
        "major_outage" -> 4
        s when s in ["degraded", "partial_outage"] -> 2
        _ -> 1
      end

    min(ms * factor, cfg.max_delay_ms)
  end

  @doc """
  The public service status (`GET /v1/status`): `{:ok, %{"status" => "operational" | "degraded" | "partial_outage" | "major_outage" | "maintenance", "components" => [%{"id" => "backend_api", "status" => ...}, ...], ...}}`.
  """
  def status(%__MODULE__{} = c) do
    case raw(c, :get, "/v1/status") do
      {:ok, %Req.Response{status: s} = r} when s in 200..299 -> {:ok, decode(r)}
      {:ok, %Req.Response{status: s} = r} -> {:error, Atlas.Error.from_response(s, decode(r), r.headers)}
      {:error, _} = e -> e
    end
  end

  # A top-level or backend_api `major_outage` is an outage; otherwise the top-level status stands.
  defp effective_status(%{"status" => top} = body) do
    backend = Enum.find(body["components"] || [], &(&1["id"] == "backend_api"))
    if top == "major_outage" or (backend && backend["status"] == "major_outage"), do: "major_outage", else: top
  end

  defp effective_status(_), do: "unknown"

  defp service_status(c) do
    key = {__MODULE__, :status, c.base_url}
    now = System.monotonic_time(:millisecond)

    case :persistent_term.get(key, nil) do
      {value, at} when now - at < 30_000 ->
        value

      _ ->
        value = case status(c) do {:ok, body} -> effective_status(body); _ -> "unknown" end
        :persistent_term.put(key, {value, now})
        value
    end
  end

  @doc false
  # Pages through a cursor list: follows `next_cursor`, else the last item id while `has_more`.
  def stream(%__MODULE__{} = c, template, bindings, opts) do
    Stream.resource(
      fn -> {:more, nil} end,
      fn
        :done ->
          {:halt, :done}

        {:more, cursor} ->
          params = (opts[:params] || []) |> Enum.to_list() |> Keyword.new(fn {k, v} -> {to_atom(k), v} end)
          params = if cursor, do: Keyword.put(params, :starting_after, cursor), else: params

          case request(c, :get, template, bindings, nil, Keyword.put(opts, :params, params)) do
            {:ok, %{"data" => items} = page} when is_list(items) -> {items, next(page, items)}
            {:ok, items} when is_list(items) -> {items, :done}
            {:ok, _} -> {[], :done}
            {:error, err} -> raise err
          end
      end,
      fn _ -> :ok end
    )
  end

  defp to_atom(k) when is_atom(k), do: k
  defp to_atom(k), do: String.to_atom(k)

  defp next(%{"has_more" => true} = page, items) do
    case page["next_cursor"] || last_id(items) do
      nil -> :done
      cursor -> {:more, cursor}
    end
  end

  defp next(%{"next_cursor" => c}, _) when is_binary(c) and c != "", do: {:more, c}
  defp next(_, _), do: :done

  defp last_id([]), do: nil
  defp last_id(items), do: with(%{"id" => id} <- List.last(items), do: id)

  defp idem(nil), do: []
  defp idem(key), do: [{"idempotency-key", key}]

  defp put_body(req, nil, _), do: req
  defp put_body(req, body, nil) when is_map(body) or is_list(body), do: Keyword.put(req, :json, body)

  defp put_body(req, body, type) when is_binary(body),
    do: req |> Keyword.put(:body, body) |> Keyword.update!(:headers, &[{"content-type", type || "application/octet-stream"} | &1])

  # Path values are percent-encoded so an id can never add a path segment.
  defp expand(template, bindings) do
    Regex.replace(~r/\{(\w+)\}/, template, fn _, name ->
      URI.encode(to_string(Map.fetch!(bindings, name)), &URI.char_unreserved?/1)
    end)
  end

  defp decode(%Req.Response{body: ""}), do: nil

  defp decode(%Req.Response{body: body} = r) do
    json? = r |> Req.Response.get_header("content-type") |> Enum.any?(&(&1 =~ "json" and not (&1 =~ "x-ndjson")))
    if json?, do: (case Jason.decode(body) do {:ok, v} -> v; _ -> body end), else: body
  end
end
