defmodule Atlas.ClientResilienceTest do
  use ExUnit.Case, async: false

  # Retry behaviour: 429 is retried and Retry-After is honoured; unsafe 5xx are not retried without an idempotency key.
  defp client(responses, extra \\ []) do
    {:ok, agent} = Agent.start_link(fn -> responses end)
    {:ok, sleeps} = Agent.start_link(fn -> [] end)
    stub = :"stub_#{System.unique_integer([:positive])}"

    Req.Test.stub(stub, fn conn ->
      {status, headers, body} = Agent.get_and_update(agent, fn [r | rest] -> {r, rest} end)
      conn = Enum.reduce(headers, conn, fn {k, v}, c -> Plug.Conn.put_resp_header(c, k, v) end)
      conn |> Plug.Conn.put_resp_content_type("application/json") |> Plug.Conn.send_resp(status, Jason.encode!(body))
    end)

    c =
      Atlas.new("sk_test_x",
        req_options: [plug: {Req.Test, stub}],
        resilience: [sleep: fn ms -> Agent.update(sleeps, &[ms | &1]) end, jitter: false] ++ extra
      )

    {c, agent, sleeps}
  end

  test "a 429 with Retry-After is waited out then succeeds" do
    {c, agent, sleeps} = client([{429, [{"retry-after", "2"}], %{"errors" => [%{"code" => "RATE_LIMITED"}]}}, {200, [], %{"ok" => true}}])
    assert {:ok, %{"ok" => true}} = Atlas.Users.list(c)
    assert Agent.get(sleeps, & &1) == [2000]
    assert Agent.get(agent, & &1) == []
  end

  test "a 503 is retried for a read with exponential backoff, and for a write only with an idempotency key" do
    {c, _agent, sleeps} = client([{503, [], %{}}, {503, [], %{}}, {200, [], %{"id" => "u1"}}])
    assert {:ok, %{"id" => "u1"}} = Atlas.Users.get(c, "u1")
    assert Agent.get(sleeps, &Enum.reverse/1) == [250, 500]

    {w, _a, wsleeps} = client([{503, [], %{}}])
    assert {:error, %Atlas.Error{status: 503}} = Atlas.Users.create(w, %{email_address: "a@example.com"})
    assert Agent.get(wsleeps, & &1) == []

    {k, _a2, ksleeps} = client([{503, [], %{}}, {201, [], %{"id" => "u2"}}])
    assert {:ok, _} = Atlas.Users.create(k, %{email_address: "a@example.com"}, idempotency_key: "k1")
    assert length(Agent.get(ksleeps, & &1)) == 1
  end

  test "a 429 is retried for a write without a key" do
    {c, _a, sleeps} = client([{429, [], %{}}, {201, [], %{"id" => "u3"}}])
    assert {:ok, _} = Atlas.Users.create(c, %{})
    assert length(Agent.get(sleeps, & &1)) == 1
  end

  test "a 500 on a write is not retried without an idempotency key, and is with one" do
    {c, _a, sleeps} = client([{500, [], %{}}])
    assert {:error, %Atlas.Error{status: 500}} = Atlas.Users.create(c, %{})
    assert Agent.get(sleeps, & &1) == []

    {c2, _a2, sleeps2} = client([{500, [], %{}}, {200, [], %{"id" => "u"}}])
    assert {:ok, _} = Atlas.Users.create(c2, %{}, idempotency_key: "k1")
    assert length(Agent.get(sleeps2, & &1)) == 1
  end

  test "a Retry-After longer than max_delay_ms is not waited out and the error carries it" do
    {c, _a, sleeps} = client([{429, [{"retry-after", "120"}], %{}}], max_delay_ms: 5_000)
    assert {:error, %Atlas.Error{status: 429, retry_after_ms: 120_000}} = Atlas.Users.list(c)
    assert Agent.get(sleeps, & &1) == []
  end

  test "retry: false in req_options turns retries off unless max_retries is given" do
    {:ok, _} = Agent.start_link(fn -> nil end)
    c = Atlas.new("sk_test_x", req_options: [plug: {Req.Test, Atlas.NoRetryStub}, retry: false])
    assert Atlas.Client.resilience(c).max_retries == 0
    assert Atlas.Client.resilience(Atlas.new("sk_test_x", req_options: [retry: false], resilience: [max_retries: 3])).max_retries == 3
  end

  test "retry events are emitted when :telemetry is installed" do
    if Code.ensure_loaded?(:telemetry) do
      id = "atlas-test-#{System.unique_integer([:positive])}"
      test_pid = self()

      :telemetry.attach_many(
        id,
        [[:atlas, :request, :stop], [:atlas, :request, :retry]],
        fn event, m, meta, _ -> send(test_pid, {:event, event, m, meta}) end,
        nil
      )

      {c, _a, _s} = client([{503, [], %{}}, {200, [], %{}}])
      assert {:ok, _} = Atlas.Users.get(c, "user_1")
      assert_received {:event, [:atlas, :request, :retry], %{attempt: 1}, %{route: "/v1/users/{id}", http_status: 503}}
      assert_received {:event, [:atlas, :request, :stop], %{duration: _}, %{status: :ok, route: "/v1/users/{id}", method: "GET"}}
      :telemetry.detach(id)
    end
  end

  describe "a connection reset before any response" do
    # Fails the first `fails` calls with a transport error, then answers 200.
    defp flaky(reason, fails) do
      {:ok, calls} = Agent.start_link(fn -> 0 end)
      {:ok, sleeps} = Agent.start_link(fn -> [] end)
      stub = :"flaky_#{System.unique_integer([:positive])}"

      Req.Test.stub(stub, fn conn ->
        if Agent.get_and_update(calls, &{&1 + 1, &1 + 1}) <= fails do
          Req.Test.transport_error(conn, reason)
        else
          conn |> Plug.Conn.put_resp_content_type("application/json") |> Plug.Conn.send_resp(200, ~s({"id":"u1"}))
        end
      end)

      c = Atlas.new("sk_test_x", req_options: [plug: {Req.Test, stub}], resilience: [sleep: fn ms -> Agent.update(sleeps, &[ms | &1]) end])
      {c, calls, sleeps}
    end

    test "is retried once for a read and for a keyed write" do
      {c, calls, sleeps} = flaky(:closed, 1)
      assert {:ok, %{"id" => "u1"}} = Atlas.Users.get(c, "u1")
      assert Agent.get(calls, & &1) == 2
      assert [ms] = Agent.get(sleeps, & &1)
      assert ms in 26..125

      {k, kcalls, _} = flaky(:econnreset, 1)
      assert {:ok, _} = Atlas.Users.create(k, %{}, idempotency_key: "k1")
      assert Agent.get(kcalls, & &1) == 2
    end

    test "is not retried for a plain write or a timeout, and a second reset is returned" do
      {c, calls, _} = flaky(:closed, 1)
      assert {:error, %Atlas.Error{code: "TRANSPORT_ERROR"}} = Atlas.Users.create(c, %{})
      assert Agent.get(calls, & &1) == 1

      {t, tcalls, _} = flaky(:timeout, 1)
      assert {:error, %Atlas.Error{code: "TRANSPORT_ERROR"}} = Atlas.Users.get(t, "u1")
      assert Agent.get(tcalls, & &1) == 1

      {d, dcalls, _} = flaky(:closed, 2)
      assert {:error, %Atlas.Error{code: "TRANSPORT_ERROR"}} = Atlas.Users.get(d, "u1")
      assert Agent.get(dcalls, & &1) == 2
    end
  end
end
