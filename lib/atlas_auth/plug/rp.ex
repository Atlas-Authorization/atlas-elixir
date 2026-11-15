if Code.ensure_loaded?(Plug.Conn) do
  defmodule AtlasAuth.Plug.RP do
    @moduledoc """
    The hosted-redirect relying party as a Plug: sign-in, callback, sign-out and (optionally) the
    back-channel logout receiver, mounted in your endpoint or router.

        # lib/my_app_web/endpoint.ex (before the router) or a router pipeline
        plug AtlasAuth.Plug.RP,
          rp: MyApp.Auth.rp(),                      # an %AtlasAuth.RP{} built once at startup
          on_signed_in: &MyApp.Auth.signed_in/4,    # (conn, user, tokens, result) -> conn
          on_sign_out: &MyApp.Auth.sign_out/1       # (conn) -> keyword for AtlasAuth.RP.sign_out/2

    Routes (paths are configurable with `:routes`): `GET /auth/sign-in` starts sign-in (`prompt`,
    `login_hint`, `ui_locales`, `max_age`, `organization`, `return_to` and your `:forward_params` pass
    through), `GET` on the path of the configured `redirect_uri` finishes it, `GET` or `POST
    /auth/sign-out` signs out, and with `routes: %{backchannel_logout: "/auth/backchannel"}` a `POST`
    there is the back-channel logout receiver (set `:on_backchannel_logout`). Any other request passes
    through untouched, so your app answers it.

    Options:

      * `:rp` - the `%AtlasAuth.RP{}` (required).
      * `:on_signed_in` - required. `(conn, user, tokens, result -> conn)`: create your own session here
        (`Plug.Conn.put_session/3`, your own cookie, ...). Return the conn; if you did not send a
        response, the plug sends the 302 to the return path and clears the sign-in cookie.
      * `:on_sign_in_error` - `(conn, %AtlasAuth.OIDC.Error{} -> conn)`; default a plain 400.
      * `:on_sign_out` - `(conn -> keyword)`: end your own session and return `AtlasAuth.RP.sign_out/2`
        options (`:sid`, `:id_token`, `:set_cookies` that clear your session cookie, ...); default `[]`.
      * `:on_backchannel_logout` - `(app_session_ids, claims -> any)`, see `AtlasAuth.RP.backchannel_handler/2`.
      * `:routes` - `%{sign_in:, callback:, sign_out:, backchannel_logout:}`.
    """
    @behaviour Plug

    import Plug.Conn

    alias AtlasAuth.{OIDC, RP}

    @impl true
    def init(opts) do
      case {opts[:rp], opts[:on_signed_in]} do
        {%RP{}, fun} when is_function(fun, 4) -> opts
        _ -> raise ArgumentError, "AtlasAuth.Plug.RP requires `:rp` (an %AtlasAuth.RP{}) and `:on_signed_in`, a 4-arity function."
      end
    end

    @impl true
    def call(conn, opts) do
      rp = opts[:rp]
      routes = opts[:routes] || %{}
      path = conn.request_path
      callback_path = routes[:callback] || URI.parse(rp.redirect_uri).path || "/"

      cond do
        conn.method == "POST" and routes[:backchannel_logout] == path and opts[:on_backchannel_logout] ->
          bc_opts = [
            issuer: rp.issuer,
            jwks_url: String.replace(rp.issuer, ~r/\/+\z/, "") <> "/.well-known/jwks.json",
            client_id: rp.client_id,
            on_logout: RP.backchannel_handler(rp, opts[:on_backchannel_logout])
          ]

          AtlasAuth.Plug.BackchannelLogout.call(conn, AtlasAuth.Plug.BackchannelLogout.init(bc_opts))

        conn.method == "GET" and path == (routes[:sign_in] || "/auth/sign-in") ->
          conn = fetch_query_params(conn)

          case RP.start(rp, conn.query_params) do
            {:ok, redirect} -> redirect(conn, redirect)
            {:error, e} -> fail(conn, opts, e)
          end

        conn.method == "GET" and path == callback_path ->
          conn = fetch_query_params(conn)
          cookie = conn |> get_req_header("cookie") |> Enum.join("; ")

          case RP.callback(rp, conn.query_params, cookie) do
            {:ok, result} ->
              conn = opts[:on_signed_in].(conn, result.user, result.tokens, result)

              case conn.state do
                :sent -> conn
                :set -> conn |> prepend_resp_headers(Enum.map(result.redirect.cookies, &{"set-cookie", &1})) |> send_resp() |> halt()
                _ -> redirect(conn, result.redirect)
              end

            {:error, %OIDC.Error{} = e} ->
              fail(conn, opts, e)
          end

        conn.method in ["GET", "POST"] and path == (routes[:sign_out] || "/auth/sign-out") ->
          so_opts = if opts[:on_sign_out], do: opts[:on_sign_out].(conn), else: []

          case RP.sign_out(rp, so_opts) do
            {:ok, redirect} ->
              redirect(conn, redirect)

            {:error, _} ->
              conn |> put_resp_header("cache-control", "no-store") |> send_resp(502, "Sign-out could not reach the sign-in service.") |> halt()
          end

        true ->
          conn
      end
    end

    defp redirect(conn, %{location: location, cookies: cookies}) do
      conn
      |> put_resp_header("location", location)
      |> put_resp_header("cache-control", "no-store")
      |> prepend_resp_headers(Enum.map(cookies, &{"set-cookie", &1}))
      |> send_resp(302, "")
      |> halt()
    end

    defp fail(conn, opts, %OIDC.Error{} = e) do
      conn = if e.clear_cookie, do: prepend_resp_headers(conn, [{"set-cookie", e.clear_cookie}]), else: conn

      case opts[:on_sign_in_error] do
        fun when is_function(fun, 2) ->
          fun.(conn, e)

        _ ->
          conn
          |> put_resp_header("cache-control", "no-store")
          |> put_resp_content_type("text/plain")
          |> send_resp(400, "Sign-in failed. Please try again.")
          |> halt()
      end
    end
  end
end
