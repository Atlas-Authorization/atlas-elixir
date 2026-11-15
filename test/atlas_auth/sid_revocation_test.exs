defmodule AtlasAuth.SidRevocationTest do
  use ExUnit.Case, async: true

  alias AtlasAuth.SidRevocation

  defp clock(start), do: elem(Agent.start_link(fn -> start end), 1)
  defp tick(c, ms), do: Agent.update(c, &(&1 + ms))

  defp start(fetch, c, extra \\ []) do
    {:ok, pid} = SidRevocation.start_link([fetch_page: fetch, now_ms: fn -> Agent.get(c, & &1) end] ++ extra)
    pid
  end

  test "a listed sid is revoked until its token cannot be live; others pass" do
    c = clock(1_000_000)
    fetch = fn _ -> {:ok, %{"data" => [%{"sid" => "s1", "revoked_at" => 1_000_000}], "has_more" => false, "server_time" => 1_000_000}} end
    pid = start(fetch, c, max_token_lifetime_seconds: 60)
    assert SidRevocation.revoked?(pid, "s1")
    refute SidRevocation.revoked?(pid, "s2")
    assert {:error, :revoked} = SidRevocation.check(pid, "s1")
    assert :ok = SidRevocation.check(pid, "s2")
    assert :ok = SidRevocation.check(pid, nil)
    tick(c, 61_000)
    refute SidRevocation.revoked?(pid, "s1")
  end

  test "pages are followed and the next poll asks from just before server_time" do
    c = clock(5_000_000)
    {:ok, calls} = Agent.start_link(fn -> [] end)

    fetch = fn params ->
      Agent.update(calls, &[params | &1])

      case params[:cursor] do
        nil -> {:ok, %{"data" => [%{"sid" => "a", "revoked_at" => 5_000_000}], "has_more" => true, "next_cursor" => "c1", "server_time" => 5_000_100}}
        "c1" -> {:ok, %{"data" => [%{"sid" => "b", "revoked_at" => 5_000_000}], "has_more" => false, "server_time" => 5_000_100}}
      end
    end

    pid = start(fetch, c, interval_ms: 1000)
    assert SidRevocation.revoked?(pid, "b")
    tick(c, 2000)
    SidRevocation.revoked?(pid, "a")
    [latest | _] = Agent.get(calls, & &1)
    assert latest[:since] == 5_000_100 - 10_000  # a 10 s overlap before server_time absorbs clock skew
  end

  test "a failed poll keeps the last list and reports the error" do
    c = clock(1_000_000)
    {:ok, n} = Agent.start_link(fn -> 0 end)

    fetch = fn _ ->
      case Agent.get_and_update(n, &{&1, &1 + 1}) do
        0 -> {:ok, %{"data" => [%{"sid" => "s1", "revoked_at" => 1_000_000}], "has_more" => false, "server_time" => 1_000_000}}
        _ -> {:error, :down}
      end
    end

    test_pid = self()
    pid = start(fetch, c, interval_ms: 1000, on_error: fn e -> send(test_pid, {:err, e}) end)
    assert SidRevocation.revoked?(pid, "s1")
    tick(c, 2000)
    assert SidRevocation.revoked?(pid, "s1")
    assert_received {:err, :down}
  end

  test "on_stale: :reject fails closed once the list is stale, :allow keeps trusting it" do
    c = clock(1_000_000)
    fetch = fn _ -> {:error, :down} end
    reject = start(fetch, c, on_stale: :reject, stale_after_ms: 1000, interval_ms: 100_000)
    allow = start(fetch, c, interval_ms: 100_000)
    tick(c, 5000)
    assert {:error, :revocation_unavailable} = SidRevocation.check(reject, "s")
    assert :ok = SidRevocation.check(allow, "s")
  end
end
