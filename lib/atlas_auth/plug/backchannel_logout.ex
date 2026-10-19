if Code.ensure_loaded?(Plug.Conn) do
  defmodule AtlasAuth.Plug.BackchannelLogout do
    @moduledoc """
    A Plug that serves an OpenID Connect back-channel logout endpoint.

    Atlas POSTs a form-encoded `logout_token` to the back-channel logout URI you
    registered for your app. This plug reads it, verifies it with
    `AtlasAuth.BackchannelLogout.verify/2`, and calls your `:on_logout` function
    with the verified claims so you can end the matching local session(s) — by
    `sid` (one session) or by `sub` (every session of that user).

        # router.ex
        forward "/auth/backchannel-logout", AtlasAuth.Plug.BackchannelLogout,
          jwks_url: "https://inst.atlas.example/.well-known/jwks.json",
          issuer: "https://inst.atlas.example",
          client_id: "your-client-id",
          on_logout: &MyApp.Sessions.end_by_logout_token/1

    Responses (always with `Cache-Control: no-store`, and the connection halted):

      * `200` — the token verified and `:on_logout` returned anything other than
        `{:error, _}`;
      * `400` — the `logout_token` is missing or fails verification;
      * `503` with `Retry-After: 30` — the issuer's keys could not be fetched
        (`:no_keys`), so Atlas retries;
      * `501` — `:on_logout` returned `{:error, _}` (the logout could not be
        completed, so Atlas may retry);
      * `405` — any method other than `POST`.

    Options:

      * `:on_logout` — required. `(claims -> any)`, called with
        `%{sub: ..., sid: ..., jti: ...,  iat: ...}`. Do your `jti` replay check
        here too (return `:ok` for an already-seen `jti`).
      * every option of `AtlasAuth.BackchannelLogout.verify/2` (`:client_id`,
        `:issuer`, `:jwks_url`, …).

    The body is read from `conn.body_params` when a `Plug.Parsers` already ran
    with the `:urlencoded` parser, otherwise read and decoded here.
    """
    @behaviour Plug

    import Plug.Conn

    alias AtlasAuth.BackchannelLogout

    @impl true
    def init(opts) do
      case Keyword.get(opts, :on_logout) do
        fun when is_function(fun, 1) ->
          opts

        _ ->
          raise ArgumentError,
                "AtlasAuth.Plug.BackchannelLogout requires :on_logout, a 1-arity function."
      end
    end

    @impl true
    def call(%Plug.Conn{method: "POST"} = conn, opts) do
      {token, conn} = logout_token(conn)

      case BackchannelLogout.verify(token, opts) do
        {:ok, claims} ->
          case Keyword.fetch!(opts, :on_logout).(claims) do
            {:error, _} -> respond(conn, 501, ~s({"error":"logout_failed"}))
            _ -> respond(conn, 200, "")
          end

        {:error, reason} ->
          if BackchannelLogout.retryable?(reason) do
            conn
            |> put_resp_header("retry-after", "30")
            |> respond(503, ~s({"error":"temporarily_unavailable"}))
          else
            respond(conn, 400, ~s({"error":"invalid_request"}))
          end
      end
    end

    def call(conn, _opts) do
      conn
      |> put_resp_header("allow", "POST")
      |> respond(405, "")
    end

    defp logout_token(%Plug.Conn{body_params: %{"logout_token" => token}} = conn)
         when is_binary(token),
         do: {token, conn}

    defp logout_token(conn) do
      case read_body(conn) do
        {:ok, body, conn} ->
          token =
            try do
              URI.decode_query(body)["logout_token"]
            rescue
              _ -> nil
            end

          {token, conn}

        _ ->
          {nil, conn}
      end
    end

    defp respond(conn, status, body) do
      conn
      |> put_resp_header("cache-control", "no-store")
      |> then(fn c ->
        if body == "", do: c, else: put_resp_content_type(c, "application/json")
      end)
      |> send_resp(status, body)
      |> halt()
    end
  end
end
