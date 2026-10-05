if Code.ensure_loaded?(Plug.Conn) do
  defmodule AtlasAuth.Plug do
    @moduledoc """
    A Plug that verifies the Atlas session on the incoming request and makes the
    result available to the rest of the pipeline.

        plug AtlasAuth.Plug, jwks_url: "https://inst.atlas.example/.well-known/jwks.json",
                             issuer: "https://inst.atlas.example"

    On every request — authenticated or not — it assigns:

      * `conn.assigns.atlas_authenticated?` — a boolean;
      * `conn.assigns.atlas_claims` — the `%AtlasAuth.Claims{}` on success, else `nil`;
      * `conn.assigns.atlas_error` — the failure reason on failure, else `nil`.

    WHY this plug never halts and always assigns, even on failure: authentication
    and *authorization* are different jobs. Some routes are public, some degrade
    gracefully for anonymous callers, and only some demand a session. So this plug
    reports what it found and leaves the policy decision to the route — or to
    `AtlasAuth.Plug.RequireAuth`, which is the one that halts. Compose them:

        plug AtlasAuth.Plug, jwks_url: ..., issuer: ...
        plug AtlasAuth.Plug.RequireAuth

    The plug is guarded by `Code.ensure_loaded?/1` because `:plug` is an optional
    dependency — an app that only wants the verifier never compiles this module.

    Options are those of `AtlasAuth.Verifier.verify/2`; `:jwks_url` and `:issuer`
    may also come from application env / `ATLAS_JWKS_URL` / `ATLAS_ISSUER`.
    """
    @behaviour Plug

    import Plug.Conn

    alias AtlasAuth.Verifier

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts) do
      case Verifier.authenticate_request(conn.req_headers, opts) do
        {:ok, claims} ->
          conn
          |> assign(:atlas_authenticated?, true)
          |> assign(:atlas_claims, claims)
          |> assign(:atlas_error, nil)

        {:error, reason} ->
          conn
          |> assign(:atlas_authenticated?, false)
          |> assign(:atlas_claims, nil)
          |> assign(:atlas_error, reason)
      end
    end
  end
end
