defmodule Atlas.BackendCoverageTest do
  # Every Backend operation in the checked-in list is reachable through exactly
  # the method and path the list names. Each generated function is really
  # called against a stub that records what it received.
  use ExUnit.Case, async: false

  @ops_file Path.join([__DIR__, "..", "fixtures", "operations.txt"])

  setup do
    {:ok, agent} = Agent.start_link(fn -> [] end)

    Req.Test.stub(Atlas.CoverageStub, fn conn ->
      Agent.update(agent, &[{conn.method, conn.request_path} | &1])
      Req.Test.json(conn, %{"data" => [], "has_more" => false})
    end)

    client = Atlas.new("sk_test", req_options: [plug: {Req.Test, Atlas.CoverageStub}, retry: false])
    {:ok, client: client, agent: agent}
  end

  defp fixture do
    @ops_file |> File.read!() |> String.split("\n", trim: true) |> MapSet.new()
  end

  test "the operation list is non-trivial and the generated modules cover every entry", %{client: client, agent: agent} do
    expected = fixture()
    assert MapSet.size(expected) >= 1000

    declared =
      for mod <- Atlas.Resources.all(), {_fun, method, path, _n, _b, _p} <- mod.__operations__(), into: MapSet.new() do
        String.upcase(to_string(method)) <> " " <> path
      end

    assert MapSet.difference(expected, declared) == MapSet.new()
    assert MapSet.difference(declared, expected) == MapSet.new()

    for mod <- Atlas.Resources.all(), {fun, method, path, n, body, paginated} <- mod.__operations__() do
      Agent.update(agent, fn _ -> [] end)
      args = [client] ++ List.duplicate("p1", n) ++ body_args(body)
      assert {:ok, _} = apply(mod, fun, args), "#{mod}.#{fun} failed"
      assert [{m, p}] = Agent.get(agent, & &1)
      assert m == method |> to_string() |> String.upcase()
      assert p == Regex.replace(~r/\{\w+\}/, path, "p1")

      if paginated do
        Agent.update(agent, fn _ -> [] end)
        assert [] == apply(mod, :"stream_#{fun}", [client] ++ List.duplicate("p1", n)) |> Enum.to_list()
        assert [{^m, ^p}] = Agent.get(agent, & &1)
      end
    end
  end

  defp body_args(false), do: []
  defp body_args(true), do: [%{}]
  defp body_args(:binary), do: [<<1, 2, 3>>]
end
