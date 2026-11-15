defmodule AtlasAuth.Telemetry do
  @moduledoc """
  `:telemetry` events for every Backend API call, opt-in and dependency-free when off: the SDK only
  emits them when the `:telemetry` application is in your dependency tree (add
  `{:telemetry, "~> 1.0"}`; `opentelemetry_telemetry` or `OpentelemetryTelemetry` then turns them into spans).

  Events:

    * `[:atlas, :request, :start]` - measurements `%{system_time:, monotonic_time:}`; metadata
      `%{method: "GET", route: "/v1/users/{id}", base_url: ...}`. `route` is the path TEMPLATE, never the
      expanded path, so ids never become metric labels.
    * `[:atlas, :request, :stop]` - measurements `%{duration:}` (native units); metadata adds
      `status: :ok | :error`, and on error `http_status` (nil for a transport failure), `code` and `request_id`.
    * `[:atlas, :request, :exception]` - the standard `:telemetry.span/3` exception event.
    * `[:atlas, :request, :retry]` - measurements `%{delay_ms:, attempt:}`; metadata `method`, `route`,
      `http_status`, `code`. Emitted before each wait.
    * `[:atlas, :doctor, :check]` - one per `Atlas.Doctor` check; measurements `%{}`, metadata `%{name:, status:}`.

  Attach a handler the usual way:

      :telemetry.attach("atlas-log", [:atlas, :request, :stop], fn _event, %{duration: d}, meta, _ ->
        ms = System.convert_time_unit(d, :native, :millisecond)
        Logger.info("atlas \#{meta.method} \#{meta.route} \#{meta.status} in \#{ms}ms")
      end, nil)
  """

  @doc false
  # Runs `fun` (returning `{result, stop_metadata}`) inside a span when :telemetry is loaded; otherwise just runs it.
  def span(event, metadata, fun) when is_function(fun, 0) do
    if enabled?() do
      apply(:telemetry, :span, [event, metadata, fun])
    else
      {result, _} = fun.()
      result
    end
  end

  @doc false
  def execute(event, measurements, metadata) do
    if enabled?(), do: apply(:telemetry, :execute, [event, measurements, metadata])
    :ok
  end

  if Code.ensure_loaded?(Telemetry.Metrics) do
    @doc """
    `Telemetry.Metrics` definitions for the request events, for any `telemetry_metrics` reporter
    (Prometheus, StatsD, LiveDashboard): `atlas.request.count` (counter), `atlas.request.duration`
    (distribution, milliseconds, buckets 5 ms to 10 s, and a summary `atlas.request.duration.summary`)
    and `atlas.request.retry.count` (counter), tagged by `method`, `route` (the path template) and
    `status` (`ok` / `error`). Needs `{:telemetry_metrics, "~> 1.0"}` in your dependencies.

        children = [{TelemetryMetricsPrometheus, metrics: AtlasAuth.Telemetry.metrics()}]
    """
    def metrics do
      import Telemetry.Metrics
      stop = [:atlas, :request, :stop]
      tags = [:method, :route, :status]

      [
        counter("atlas.request.count", event_name: stop, measurement: :duration, tags: tags),
        distribution("atlas.request.duration",
          event_name: stop,
          measurement: :duration,
          unit: {:native, :millisecond},
          tags: tags,
          reporter_options: [buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10_000]]
        ),
        summary("atlas.request.duration.summary", event_name: stop, measurement: :duration, unit: {:native, :millisecond}, tags: tags),
        counter("atlas.request.retry.count", event_name: [:atlas, :request, :retry], measurement: :attempt, tags: [:method, :route, :http_status])
      ]
    end
  else
    @doc "Needs `{:telemetry_metrics, \"~> 1.0\"}`; raises without it."
    def metrics, do: raise(RuntimeError, "AtlasAuth.Telemetry.metrics/0 needs the :telemetry_metrics dependency")
  end

  @doc "Whether `:telemetry` is available (events are only emitted then)."
  def enabled?, do: Code.ensure_loaded?(:telemetry)
end
