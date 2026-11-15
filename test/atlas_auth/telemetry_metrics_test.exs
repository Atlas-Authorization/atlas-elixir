defmodule AtlasAuth.TelemetryMetricsTest do
  use ExUnit.Case, async: true

  if Code.ensure_loaded?(Telemetry.Metrics) do
    test "metrics/0 defines count, duration and retry metrics tagged by method, route and status" do
      metrics = AtlasAuth.Telemetry.metrics()
      names = Enum.map(metrics, & &1.name)
      assert [:atlas, :request, :count] in names
      assert [:atlas, :request, :duration] in names
      assert [:atlas, :request, :retry, :count] in names
      request = Enum.find(metrics, &(&1.name == [:atlas, :request, :count]))
      assert request.tags == [:method, :route, :status]
      assert request.event_name == [:atlas, :request, :stop]
      dist = Enum.find(metrics, &(&1.name == [:atlas, :request, :duration]))
      assert %Telemetry.Metrics.Distribution{} = dist
    end
  else
    test "metrics/0 raises without telemetry_metrics" do
      assert_raise RuntimeError, ~r/telemetry_metrics/, fn -> AtlasAuth.Telemetry.metrics() end
    end
  end
end
