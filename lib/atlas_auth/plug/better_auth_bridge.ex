if Code.ensure_loaded?(Plug.Conn) do
  defmodule AtlasAuth.Plug.BetterAuthBridge do
    @moduledoc """
    The Better Auth session bridge as a Plug: a `GET` / `HEAD` carrying a Better Auth
    session cookie is exchanged once (Backend API, secret key, forwarding the end
    user's IP and user agent) and answered with a `307` to the same URL, the Atlas
    session cookies set and the Better Auth cookies cleared — so the next request is
    signed in and nobody is logged out by the switch. A user who still owes a second
    factor is redirected to `:sign_in_url` with `__atlas_attempt` / `__atlas_status`.
    Anything else (no Better Auth cookie, an Atlas session already present, the bridge
    closed, Atlas unreachable) passes through untouched.

        plug AtlasAuth.Plug.BetterAuthBridge,
          secret_key: System.fetch_env!("ATLAS_SECRET_KEY"),
          sign_in_url: "/sign-in"

        plug AtlasAuth.Plug, jwks_url: ..., issuer: ...

    Or pass `better_auth_bridge: [sign_in_url: "/sign-in"]` (or `true`) to
    `AtlasAuth.Plug`, which runs it first.

    Options: those of `AtlasAuth.BetterAuth.decide/2` (`:secret_key`, `:api_url`,
    `:cookie_prefix`, `:cookie_name`, `:cookie_domain`, `:secure`, `:poster`) plus
    `:sign_in_url` (default: the requested URL) and `:trust_forwarded_for` (default
    `true`: the end user's IP is the first `X-Forwarded-For` hop, else `X-Real-IP`,
    else `conn.remote_ip`; set `false` when no proxy you control sets them).
    """
    @behaviour Plug

    import Plug.Conn

    alias AtlasAuth.BetterAuth

    @impl true
    def init(opts) when is_list(opts), do: opts
    def init(true), do: []

    @impl true
    def call(%Plug.Conn{method: method} = conn, opts) when method in ["GET", "HEAD"] do
      cookie = conn |> get_req_header("cookie") |> Enum.join("; ")

      decision =
        BetterAuth.decide(
          cookie,
          Keyword.merge(opts, client_ip: client_ip(conn, opts), user_agent: user_agent(conn))
        )

      if BetterAuth.redirect?(decision) do
        here =
          conn.request_path <>
            if(conn.query_string in [nil, ""], do: "", else: "?" <> conn.query_string)

        location =
          if decision.action == :needs_mfa,
            do:
              BetterAuth.continuation_url(
                opts[:sign_in_url] || here,
                decision.attempt_id,
                decision.status
              ),
            else: here

        conn
        |> prepend_resp_headers(
          Enum.map(decision.cookies, &{"set-cookie", BetterAuth.serialize_cookie(&1)})
        )
        |> put_resp_header("location", location)
        |> put_resp_header("cache-control", "no-store")
        |> send_resp(307, "")
        |> halt()
      else
        conn
      end
    end

    def call(conn, _opts), do: conn

    defp client_ip(conn, opts) do
      forwarded =
        if Keyword.get(opts, :trust_forwarded_for, true) != false,
          do: BetterAuth.client_ip_from_headers(conn.req_headers)

      forwarded || format_ip(conn.remote_ip)
    end

    defp format_ip(nil), do: nil

    defp format_ip(ip) do
      case :inet.ntoa(ip) do
        {:error, _} -> nil
        chars -> to_string(chars)
      end
    end

    defp user_agent(conn), do: conn |> get_req_header("user-agent") |> List.first()
  end
end
