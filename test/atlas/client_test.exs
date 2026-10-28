defmodule Atlas.ClientTest do
  use ExUnit.Case, async: true

  defp client(stub), do: Atlas.new("sk_test_abc", req_options: [plug: {Req.Test, stub}, retry: false])

  test "sends bearer auth, JSON body and idempotency key; decodes the response" do
    Req.Test.stub(:create, fn conn ->
      {:ok, raw, conn} = Plug.Conn.read_body(conn)
      assert conn.method == "POST"
      assert conn.request_path == "/v1/users"
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer sk_test_abc"]
      assert Plug.Conn.get_req_header(conn, "idempotency-key") == ["k1"]
      assert Jason.decode!(raw) == %{"email_address" => "a@example.com"}
      conn |> Plug.Conn.put_status(201) |> Req.Test.json(%{"id" => "user_1"})
    end)

    assert {:ok, %{"id" => "user_1"}} =
             Atlas.Users.create(client(:create), %{"email_address" => "a@example.com"}, idempotency_key: "k1")
  end

  test "path parameters are percent-encoded and query params are sent" do
    Req.Test.stub(:enc, fn conn ->
      assert conn.request_path == "/v1/users/a%2Fb%20c"
      assert conn.query_string == "expand=orgs"
      Req.Test.json(conn, %{})
    end)

    assert {:ok, _} = Atlas.Users.get(client(:enc), "a/b c", params: [expand: "orgs"])
  end

  test "an error response becomes %Atlas.Error{} with the Atlas code and request id" do
    Req.Test.stub(:err, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("x-request-id", "req_9")
      |> Plug.Conn.put_status(403)
      |> Req.Test.json(%{"errors" => [%{"code" => "INSUFFICIENT_SCOPE", "message" => "no", "meta" => %{"required_scope" => "users:write"}}]})
    end)

    assert {:error, %Atlas.Error{status: 403, code: "INSUFFICIENT_SCOPE", required_scope: "users:write", request_id: "req_9"}} =
             Atlas.Users.get(client(:err), "u1")
  end

  test "a 204 is {:ok, nil} and a non-JSON error still yields an Atlas.Error" do
    Req.Test.stub(:nocontent, fn conn -> Plug.Conn.send_resp(conn, 204, "") end)
    assert {:ok, nil} = Atlas.Users.delete(client(:nocontent), "u1")

    Req.Test.stub(:html, fn conn -> Plug.Conn.send_resp(conn, 502, "bad gateway") end)
    assert {:error, %Atlas.Error{status: 502, code: "HTTP_502"}} = Atlas.Users.get(client(:html), "u1")
  end

  test "a transport failure is an Atlas.Error with no status" do
    Req.Test.stub(:down, fn conn -> Req.Test.transport_error(conn, :econnrefused) end)
    assert {:error, %Atlas.Error{status: nil, code: "TRANSPORT_ERROR"}} = Atlas.Users.get(client(:down), "u1")
  end

  test "stream_list follows next_cursor across pages and stops when has_more is false" do
    Req.Test.stub(:pages, fn conn ->
      case URI.decode_query(conn.query_string)["starting_after"] do
        nil -> Req.Test.json(conn, %{"data" => [%{"id" => "u1"}, %{"id" => "u2"}], "has_more" => true, "next_cursor" => "c2"})
        "c2" -> Req.Test.json(conn, %{"data" => [%{"id" => "u3"}], "has_more" => false, "next_cursor" => nil})
      end
    end)

    assert ["u1", "u2", "u3"] == :pages |> client() |> Atlas.Users.stream_list() |> Enum.map(& &1["id"])
  end

  test "stream_list falls back to the last id and raises Atlas.Error on a failed page" do
    Req.Test.stub(:fallback, fn conn ->
      case URI.decode_query(conn.query_string)["starting_after"] do
        nil -> Req.Test.json(conn, %{"data" => [%{"id" => "u1"}], "has_more" => true})
        "u1" -> conn |> Plug.Conn.put_status(500) |> Req.Test.json(%{"errors" => [%{"code" => "INTERNAL", "message" => "x"}]})
      end
    end)

    assert_raise Atlas.Error, fn -> :fallback |> client() |> Atlas.Users.stream_list() |> Enum.to_list() end
  end

  test "non-JSON success bodies are returned raw" do
    Req.Test.stub(:raw, fn conn ->
      conn |> Plug.Conn.put_resp_content_type("application/gzip") |> Plug.Conn.send_resp(200, <<31, 139, 8>>)
    end)

    assert {:ok, <<31, 139, 8>>} = Atlas.Users.get(client(:raw), "u1")
  end
end
