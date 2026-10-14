defmodule AtlasAuth.Plug.BackchannelLogoutTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AtlasAuth.TokenHelper
  alias AtlasAuth.Plug.BackchannelLogout

  setup do
    test_pid = self()

    opts =
      TokenHelper.verify_opts(
        client_id: TokenHelper.client_id(),
        on_logout: fn claims ->
          send(test_pid, {:logged_out, claims})
          :ok
        end
      )

    {:ok, opts: opts}
  end

  defp post_form(body, opts) do
    conn(:post, "/backchannel-logout", body)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> BackchannelLogout.call(BackchannelLogout.init(opts))
  end

  test "200 + no-store and the callback receives the claims", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"jti" => "jti_plug"})
    conn = post_form(URI.encode_query(%{"logout_token" => token}), opts)

    assert conn.status == 200
    assert conn.halted
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert_received {:logged_out, %{sid: "sess_2def", sub: "user_2abc", jti: "jti_plug"}}
  end

  test "reads already-parsed body_params", %{opts: opts} do
    token = TokenHelper.sign_logout()

    conn =
      conn(:post, "/backchannel-logout", %{"logout_token" => token})
      |> BackchannelLogout.call(BackchannelLogout.init(opts))

    assert conn.status == 200
    assert_received {:logged_out, _}
  end

  test "400 + no-store on an invalid token, callback not invoked", %{opts: opts} do
    token = TokenHelper.sign_logout(%{"nonce" => "x"})
    conn = post_form(URI.encode_query(%{"logout_token" => token}), opts)

    assert conn.status == 400
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    refute_received {:logged_out, _}
  end

  test "400 on a missing logout_token", %{opts: opts} do
    conn = post_form("", opts)
    assert conn.status == 400
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    refute_received {:logged_out, _}
  end

  test "501 when the callback reports a failure", %{opts: opts} do
    opts = Keyword.put(opts, :on_logout, fn _ -> {:error, :store_down} end)
    conn = post_form(URI.encode_query(%{"logout_token" => TokenHelper.sign_logout()}), opts)
    assert conn.status == 501
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "405 for a non-POST request", %{opts: opts} do
    conn =
      conn(:get, "/backchannel-logout") |> BackchannelLogout.call(BackchannelLogout.init(opts))

    assert conn.status == 405
    assert get_resp_header(conn, "allow") == ["POST"]
  end

  test "init requires :on_logout" do
    assert_raise ArgumentError, fn -> BackchannelLogout.init([]) end
  end
end
