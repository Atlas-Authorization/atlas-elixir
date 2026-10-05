if Code.ensure_loaded?(Plug.Conn) do
  defmodule AtlasAuth.Plug.RequireAuth do
    @moduledoc """
    A Plug that halts unauthenticated requests with `401`.

    Run it *after* `AtlasAuth.Plug`, which does the verification and assigns
    `:atlas_authenticated?`. When that flag is true the request passes through
    untouched; otherwise the connection is halted with a JSON `401` and the route
    never runs.

        plug AtlasAuth.Plug, jwks_url: ..., issuer: ...
        plug AtlasAuth.Plug.RequireAuth

    WHY it reads an assign rather than verifying again: verification is the
    expensive part (a signature check, occasionally a JWKS fetch). Doing it once
    in `AtlasAuth.Plug` and letting every downstream gate read the cached result
    keeps a request to a single verification, and keeps authorization gates cheap
    enough to stack several on a route.

    WHY it treats a *missing* assign as unauthenticated: if `AtlasAuth.Plug` never
    ran, the pipeline is misconfigured and the safe reading of "I was told to
    require auth but nothing authenticated" is to deny.
    """
    @behaviour Plug

    import Plug.Conn

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, _opts) do
      if conn.assigns[:atlas_authenticated?] == true do
        conn
      else
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, ~s({"error":"unauthenticated"}))
        |> halt()
      end
    end
  end
end
