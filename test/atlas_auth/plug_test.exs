defmodule AtlasAuth.PlugTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AtlasAuth.{Claims, TokenHelper}

  setup do
    {:ok, opts: TokenHelper.verify_opts()}
  end

  describe "AtlasAuth.Plug" do
    test "assigns claims on a valid Bearer token", %{opts: opts} do
      token = TokenHelper.sign()

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer " <> token)
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))

      assert conn.assigns.atlas_authenticated? == true
      assert %Claims{sub: "user_2abc"} = conn.assigns.atlas_claims
      assert conn.assigns.atlas_error == nil
      refute conn.halted
    end

    test "assigns the __session cookie's token", %{opts: opts} do
      token = TokenHelper.sign(%{"sub" => "cookie_user"})

      conn =
        conn(:get, "/")
        |> put_req_header("cookie", "__session=" <> token)
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))

      assert conn.assigns.atlas_authenticated? == true
      assert %Claims{sub: "cookie_user"} = conn.assigns.atlas_claims
    end

    test "marks unauthenticated (without halting) on a missing token", %{opts: opts} do
      conn = conn(:get, "/") |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))

      assert conn.assigns.atlas_authenticated? == false
      assert conn.assigns.atlas_claims == nil
      assert conn.assigns.atlas_error == :malformed
      refute conn.halted
    end

    test "marks unauthenticated on an invalid token", %{opts: opts} do
      bad = TokenHelper.sign(%{"iss" => "https://evil.example"})

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer " <> bad)
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))

      assert conn.assigns.atlas_authenticated? == false
      assert conn.assigns.atlas_error == :invalid
    end
  end

  describe "AtlasAuth.Plug.RequireAuth" do
    test "passes an authenticated request through", %{opts: opts} do
      token = TokenHelper.sign()

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer " <> token)
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))
        |> AtlasAuth.Plug.RequireAuth.call(AtlasAuth.Plug.RequireAuth.init([]))

      refute conn.halted
    end

    test "halts with 401 when the token is missing", %{opts: opts} do
      conn =
        conn(:get, "/")
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))
        |> AtlasAuth.Plug.RequireAuth.call(AtlasAuth.Plug.RequireAuth.init([]))

      assert conn.halted
      assert conn.status == 401
      assert conn.resp_body =~ "unauthenticated"
    end

    test "halts with 401 when the token is invalid", %{opts: opts} do
      bad = TokenHelper.sign(%{"iss" => "https://evil.example"})

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer " <> bad)
        |> AtlasAuth.Plug.call(AtlasAuth.Plug.init(opts))
        |> AtlasAuth.Plug.RequireAuth.call(AtlasAuth.Plug.RequireAuth.init([]))

      assert conn.halted
      assert conn.status == 401
    end

    test "halts with 401 when AtlasAuth.Plug never ran" do
      conn =
        conn(:get, "/")
        |> AtlasAuth.Plug.RequireAuth.call(AtlasAuth.Plug.RequireAuth.init([]))

      assert conn.halted
      assert conn.status == 401
    end
  end
end
