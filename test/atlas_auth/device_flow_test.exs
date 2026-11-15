defmodule AtlasAuth.DeviceFlowTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.DeviceFlow

  @device %{"device_code" => "dc_1", "user_code" => "ABCD-EFGH", "verification_uri" => "https://i.example/oauth2/device", "expires_in" => 600, "interval" => 5}

  defp server(answers) do
    {:ok, agent} = Agent.start_link(fn -> %{answers: answers, calls: []} end)

    http = fn _m, url, _h, body ->
      {status, json} =
        Agent.get_and_update(agent, fn s ->
          [a | rest] = s.answers
          {a, %{s | answers: rest, calls: [{url, URI.decode_query(body)} | s.calls]}}
        end)

      {:ok, %{status: status, headers: [], body: Jason.encode!(json)}}
    end

    {agent, http}
  end

  test "starts at the device endpoint and polls through pending and slow_down" do
    {agent, http} =
      server([
        {200, @device},
        {400, %{"error" => "authorization_pending"}},
        {400, %{"error" => "slow_down"}},
        {200, %{"access_token" => "at_1", "token_type" => "Bearer"}}
      ])

    {:ok, flow} = DeviceFlow.start(issuer: "https://i.example/", client_id: "cli", scope: ["openid", "profile"], resource: "https://r.example", http: http)
    assert flow.user_code == "ABCD-EFGH"
    {:ok, waits} = Agent.start_link(fn -> [] end)
    assert {:ok, %{"access_token" => "at_1"}} = DeviceFlow.poll(flow, sleep: fn ms -> Agent.update(waits, &[ms | &1]) end)
    assert Agent.get(waits, &Enum.reverse/1) == [5000, 5000, 10_000]

    calls = Agent.get(agent, &Enum.reverse(&1.calls))
    assert [{"https://i.example/oauth2/device_authorization", first} | rest] = calls
    assert first["client_id"] == "cli" and first["scope"] == "openid profile" and first["resource"] == "https://r.example"

    for {url, form} <- rest do
      assert url == "https://i.example/oauth2/token"
      assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code" and form["device_code"] == "dc_1"
      refute Map.has_key?(form, "client_secret")
    end
  end

  test "a denial and a client without the device grant are errors" do
    {_, http} = server([{200, @device}, {400, %{"error" => "access_denied", "error_description" => "The user denied the request."}}])
    {:ok, flow} = DeviceFlow.start(issuer: "https://i.example", client_id: "c", client_secret: "s", http: http)
    assert {:error, %{error: "access_denied", status: 400}} = DeviceFlow.poll(flow, sleep: fn _ -> :ok end)

    {_, http2} = server([{400, %{"error" => "unauthorized_client", "error_description" => "no device grant"}}])
    assert {:error, %{error: "unauthorized_client", status: 400}} = DeviceFlow.start(issuer: "https://i.example", client_id: "c", http: http2)
  end

  test "an expired code ends the poll" do
    {_, http} = server([{200, %{@device | "expires_in" => 1}}])
    {:ok, flow} = DeviceFlow.start(issuer: "https://i.example", client_id: "c", http: http)
    clock = :counters.new(1, [])
    now = fn -> :counters.add(clock, 1, 2_000) && :counters.get(clock, 1) end
    assert {:error, %{error: "expired_token"}} = DeviceFlow.poll(flow, sleep: fn _ -> :ok end, now_ms: now)
  end
end
