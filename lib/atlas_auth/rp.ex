defmodule AtlasAuth.RP do
  @moduledoc """
  The server-side relying party for the hosted redirect: sign-in, callback, keep-alive,
  step-up and sign-out, as plain functions over a `%AtlasAuth.RP{}` you build once at
  startup. `AtlasAuth.Plug.RP` mounts them as routes in a Plug / Phoenix app.

      rp =
        AtlasAuth.RP.new(
          issuer: "https://inst.atlas.example",
          client_id: "your-client-id",
          client_secret: System.fetch_env!("ATLAS_CLIENT_SECRET"),
          redirect_uri: "https://app.example.com/auth/callback",
          secret: System.fetch_env!("ATLAS_RP_SECRET"),       # 32+ characters
          secret_key: System.get_env("ATLAS_SECRET_KEY")      # sessions:write, for keep-alive and revoke
        )

      {:ok, %{location: url, cookies: cookies}} = AtlasAuth.RP.start(rp, %{"return_to" => "/dashboard"})
      {:ok, %{user: user, tokens: tokens, redirect: redirect}} = AtlasAuth.RP.callback(rp, query_params, cookie_header)

  Everything is a thin layer over `AtlasAuth.OIDC` (state, nonce and PKCE S256 in one
  sealed short-lived cookie; ID-token checks) plus the Atlas session calls an app that
  keeps its own session needs: keep-alive (`POST /v1/sessions/{id}/touch`) and server-side
  sign-out (`POST /v1/sessions/{id}/revoke`, or with `server_sign_out: true` the one-call
  `POST /v1/oauth_clients/{id}/logout`). An app with no instance secret key (Sign in with
  Atlas, issuer `https://atlasauth.net`) keeps its own sign-in alive and ends it with its
  client credentials instead (`POST {issuer}/oauth2/session/touch` and `/oauth2/session/end`).

  ## Options of `new/1`

    * `:issuer`, `:client_id`, `:redirect_uri`, `:secret` (32+ characters) - required.
    * `:client_secret`, `:client_auth` - the confidential client; without a `:secret_key` it also
      authenticates `touch_if_due/3` and `end_app_session/2`.
    * `:scope` (default `openid profile email`), `:after_sign_in_path` (default `/`),
      `:post_logout_redirect_uri`, `:cookie_name` (default `atlas_oidc`).
    * `:secret_key`, `:api_url` (default `https://api.atlasauth.net`), `:server_sign_out`,
      `:touch_interval_ms` (default 5 minutes).
    * `:forward_params` - query parameters passed from your sign-in URL to authorize unchanged,
      for example `["ref", "utm_source"]` for referral attribution.
    * `:sid_store` - an `AtlasAuth.RP.SidStore` module or `{module, state}` (see `bind_session/4`).
    * `:http`, `:now_ms`, `:fetcher` - an HTTP function, a clock and a JWKS fetcher, for tests.
  """

  alias AtlasAuth.{Http, OIDC}
  alias AtlasAuth.OIDC.Error

  @confirm_now_window_seconds 60
  @not_forwardable ~w(response_type client_id redirect_uri state nonce code_challenge code_challenge_method scope return_to id_token_hint request request_uri)
  @default_api "https://api.atlasauth.net"

  defstruct [
    :issuer,
    :client_id,
    :client_secret,
    :client_auth,
    :redirect_uri,
    :secret,
    :scope,
    :post_logout_redirect_uri,
    :secret_key,
    :sid_store,
    :http,
    :now_ms,
    :fetcher,
    after_sign_in_path: "/",
    cookie_name: "atlas_oidc",
    api_url: @default_api,
    server_sign_out: false,
    touch_interval_ms: 300_000,
    forward_params: []
  ]

  @type t :: %__MODULE__{}

  @typedoc "Who signed in: the ID-token claims an app needs."
  @type user :: %{
          required(:sub) => String.t(),
          required(:sid) => String.t() | nil,
          required(:email) => String.t() | nil,
          required(:email_verified) => boolean(),
          required(:name) => String.t() | nil,
          required(:auth_time) => integer() | nil,
          optional(:external_id) => String.t(),
          optional(:org_id) => String.t(),
          optional(:org_role) => String.t()
        }

  @doc "Seconds `require_recent_auth/3` with `max_age` 0 stays satisfied after the confirmation."
  def confirm_now_window_seconds, do: @confirm_now_window_seconds

  @doc "Build a relying party from options (see the module docs). Raises `ArgumentError` on a bad configuration."
  @spec new(keyword()) :: t()
  def new(opts) do
    for key <- [:issuer, :client_id, :redirect_uri] do
      if not (is_binary(opts[key]) and opts[key] != ""), do: raise(ArgumentError, "AtlasAuth.RP: `#{inspect(key)}` is required.")
    end

    if not (is_binary(opts[:secret]) and byte_size(opts[:secret]) >= 32),
      do: raise(ArgumentError, "AtlasAuth.RP: `:secret` (at least 32 characters) is required to seal the sign-in cookie.")

    after_path = opts[:after_sign_in_path] || "/"

    if not OIDC.safe_return_to?(after_path),
      do: raise(ArgumentError, "AtlasAuth.RP: `:after_sign_in_path` must be a path starting with a single `/`.")

    forward = opts[:forward_params] || []

    for name <- forward do
      if not (is_binary(name) and Regex.match?(~r/\A[A-Za-z0-9_.-]{1,64}\z/, name)) or name in @not_forwardable,
        do: raise(ArgumentError, "AtlasAuth.RP: `:forward_params` cannot forward #{inspect(name)}: use a plain parameter name the helper does not set itself.")
    end

    struct!(__MODULE__, Keyword.put(opts, :after_sign_in_path, after_path))
  end

  # -- sign-in --------------------------------------------------------------------

  @doc """
  Begin sign-in: `{:ok, %{location: url, cookies: [set_cookie]}}`, a 302 to `/oauth2/authorize`
  with the sign-in cookie set. `params` is the sign-in request's query (string keys):
  `prompt`, `login_hint`, `ui_locales`, `max_age`, `organization` and `return_to` pass through
  (a bad `return_to` is dropped, never an error), as do the `:forward_params` you configured.
  `overrides` (keyword: `:prompt`, `:login_hint`, `:ui_locales`, `:max_age`, `:organization`,
  `:return_to`, `:expected_sub`, `:scope`, `:extra_params`) win.
  """
  @spec start(t(), map(), keyword()) :: {:ok, %{location: String.t(), cookies: [String.t()]}} | {:error, Error.t()}
  def start(%__MODULE__{} = rp, params \\ %{}, overrides \\ []) do
    params = stringify(params)

    from_query =
      [
        prompt: params["prompt"],
        login_hint: params["login_hint"],
        ui_locales: params["ui_locales"],
        organization: params["organization"],
        return_to: if(OIDC.safe_return_to?(params["return_to"]), do: params["return_to"]),
        max_age: with(m when is_binary(m) <- params["max_age"], true <- Regex.match?(~r/\A\d{1,9}\z/, m), do: String.to_integer(m), else: (_ -> nil))
      ]
      |> Enum.reject(fn {_, v} -> is_nil(v) end)

    forwarded =
      for name <- rp.forward_params, v = params[name], is_binary(v), byte_size(v) <= 512, into: %{}, do: {name, v}

    extra = Map.merge(forwarded, Map.new(overrides[:extra_params] || %{}, fn {k, v} -> {to_string(k), v} end))

    opts =
      oidc_base(rp)
      |> Keyword.put(:scope, rp.scope)
      |> Keyword.merge(from_query)
      |> Keyword.merge(Keyword.delete(overrides, :extra_params))
      |> Keyword.put(:extra_params, extra)

    with {:ok, %{url: url, cookie: cookie}} <- OIDC.start(opts), do: {:ok, %{location: url, cookies: [cookie]}}
  end

  @doc """
  Finish sign-in. `query` is the callback's query params, `cookie` the request's `Cookie` header.

  `{:ok, %{user:, tokens:, identity:, redirect:}}` where `redirect` is `%{location:, cookies:}`,
  a 302 to the return path (or `:after_sign_in_path`) that already clears the sign-in cookie:
  create your session for `user.sub`, keep `user.sid` on it, and add your own cookie to the
  redirect. On failure `{:error, %AtlasAuth.OIDC.Error{}}`: answer 400 and send its `clear_cookie`.
  """
  @spec callback(t(), map() | String.t(), String.t() | nil) :: {:ok, map()} | {:error, Error.t()}
  def callback(%__MODULE__{} = rp, query, cookie) do
    opts =
      oidc_base(rp) ++
        [client_secret: rp.client_secret, client_auth: rp.client_auth, query: query, cookie: cookie]

    with {:ok, id} <- OIDC.callback(opts) do
      c = id.claims

      user =
        %{sub: id.sub, sid: id.sid, email: id.email, email_verified: id.email_verified, name: id.name, auth_time: id.auth_time}
        |> put_if(:external_id, if(is_binary(c["external_id"]) and c["external_id"] != "", do: c["external_id"]))
        |> put_if(:org_id, id.organization && id.organization.id)
        |> put_if(:org_role, id.organization && id.organization.role)

      tokens = %{id_token: id.id_token, access_token: id.access_token, refresh_token: id.refresh_token, expires_at: id.expires_at}

      {:ok,
       %{
         user: user,
         tokens: tokens,
         identity: id,
         redirect: %{location: id.return_to || rp.after_sign_in_path, cookies: [id.clear_cookie]}
       }}
    end
  end

  @doc """
  Step-up. `:ok` when `auth_time` is within `max_age_seconds`; otherwise `{:redirect, %{location:, cookies:}}`
  asking the same user to authenticate again (`max_age`, plus `prompt=login` for 0). The callback then
  refuses another user or an old `auth_time`; store the new `user.auth_time`. `0` asks unless the user
  authenticated in the last #{@confirm_now_window_seconds} seconds, so the request that returns from
  the confirmation goes through.

  Options: `:sub` (required, the signed-in user), `:auth_time` (stored at sign-in), `:return_to`
  (default: `:request_path`, which you pass as the current path and query).
  """
  @spec require_recent_auth(t(), non_neg_integer(), keyword()) :: :ok | {:redirect, map()} | {:error, Error.t()}
  def require_recent_auth(%__MODULE__{} = rp, max_age_seconds, opts) when is_integer(max_age_seconds) and max_age_seconds >= 0 do
    sub = opts[:sub]
    if not (is_binary(sub) and sub != ""), do: raise(ArgumentError, "require_recent_auth: `:sub` is required.")
    at = opts[:auth_time]
    # 0 means "confirm now": it still passes for a minute after the confirmation,
    # or the request that comes back from it would be sent to confirm again, forever.
    allowed = if max_age_seconds == 0, do: @confirm_now_window_seconds, else: max_age_seconds

    if is_number(at) and now_ms(rp) / 1000 - at <= allowed do
      :ok
    else
      return_to = opts[:return_to] || opts[:request_path]

      start_opts =
        oidc_base(rp)
        |> Keyword.put(:scope, rp.scope)
        |> Keyword.put(:max_age, max_age_seconds)
        |> Keyword.put(:expected_sub, sub)
        |> then(&if(max_age_seconds == 0, do: Keyword.put(&1, :prompt, "login"), else: &1))
        |> then(&if(OIDC.safe_return_to?(return_to), do: Keyword.put(&1, :return_to, return_to), else: &1))

      with {:ok, %{url: url, cookie: cookie}} <- OIDC.start(start_opts), do: {:redirect, %{location: url, cookies: [cookie]}}
    end
  end

  def require_recent_auth(_rp, _max_age, _opts), do: raise(ArgumentError, "require_recent_auth: `max_age_seconds` must be a whole number of seconds, 0 or more.")

  # -- the Atlas session ------------------------------------------------------------

  @typedoc "The result of `touch_if_due/3`."
  @type touch_result ::
          {:skipped, integer()}
          | {:touched, %{last_touched_at: integer(), idle_expires_at: String.t() | nil}}
          | {:ended, :revoked | :idle_expired | :expired | :not_found}
          | {:error, term()}

  @doc """
  Keep the Atlas session alive while the user is active in your app, at most once per
  `:touch_interval_ms` per session. Call it on each authenticated request with the `sid` and the
  time you last touched (0 or `nil` at first). With a `:secret_key` it touches the Atlas session
  (`/v1/sessions/{id}/touch`); without one but with a `:client_secret` it touches this app's own
  sign-in (`POST {issuer}/oauth2/session/touch`), where a sid with no live sign-in of this app is
  `{:ended, :not_found}`. `{:ended, reason}`: the Atlas session is over, end your own. Any other
  failure (a key, scope or availability problem) is `{:error, %Atlas.Error{} | term}`, never
  "signed out".
  """
  @spec touch_if_due(t(), String.t(), integer() | nil) :: touch_result()
  def touch_if_due(%__MODULE__{} = rp, sid, last_touched_at) do
    now = now_ms(rp)

    cond do
      is_integer(last_touched_at) and now - last_touched_at < rp.touch_interval_ms and now >= last_touched_at ->
        {:skipped, last_touched_at}

      rp.secret_key in [nil, ""] ->
        case app_session_call(rp, sid, "touch") do
          {:ok, %{status: s} = res} when s in 200..299 ->
            idle =
              case (Http.json(res) || %{})["idle_expires_at"] do
                n when is_integer(n) -> DateTime.from_unix!(n, :millisecond) |> DateTime.to_iso8601()
                b when is_binary(b) -> b
                _ -> nil
              end

            {:touched, %{last_touched_at: now, idle_expires_at: idle}}

          {:ok, %{status: 404} = res} ->
            if (Http.json(res) || %{})["error"] == "session_not_found", do: {:ended, :not_found}, else: {:error, oauth_failure(res)}

          {:ok, res} ->
            {:error, oauth_failure(res)}

          {:error, _} = e ->
            e
        end

      true ->
        case session_call(rp, sid, "touch") do
          {:ok, %{status: s} = res} when s in 200..299 ->
            idle = (Http.json(res) || %{})["idle_expires_at"]
            {:touched, %{last_touched_at: now, idle_expires_at: if(is_binary(idle), do: idle)}}

          {:ok, %{status: 404}} ->
            {:ended, :not_found}

          {:ok, %{status: 409} = res} ->
            case error_code(res) do
              "SESSION_REVOKED" -> {:ended, :revoked}
              "SESSION_IDLE_EXPIRED" -> {:ended, :idle_expired}
              _ -> {:ended, :expired}
            end

          {:ok, res} ->
            {:error, api_failure(res)}

          {:error, _} = e ->
            e
        end
    end
  end

  @doc """
  End the Atlas session server-side (`POST /v1/sessions/{id}/revoke`); every app signed in through
  it gets a back-channel logout. An already-ended session is `{:ok, :revoked}` too; `{:ok, :not_found}`
  means this instance has no such session (check you use the same instance's secret key).
  """
  @spec revoke_session(t(), String.t()) :: {:ok, :revoked | :not_found} | {:error, term()}
  def revoke_session(%__MODULE__{} = rp, sid) do
    case session_call(rp, sid, "revoke") do
      {:ok, %{status: s}} when s in 200..299 -> {:ok, :revoked}
      {:ok, %{status: 404}} -> {:ok, :not_found}
      {:ok, res} -> {:error, api_failure(res)}
      {:error, _} = e -> e
    end
  end

  @doc """
  End THIS app's sign-in under `sid` with the app's client credentials (`POST {issuer}/oauth2/session/end`):
  its refresh grants are revoked and Atlas sends the app a back-channel logout. The Atlas session and
  other apps are untouched. Needs `:client_secret`.
  """
  @spec end_app_session(t(), String.t()) :: {:ok, :ended | :not_found} | {:error, term()}
  def end_app_session(%__MODULE__{} = rp, sid) do
    case app_session_call(rp, sid, "end") do
      {:ok, %{status: s}} when s in 200..299 ->
        {:ok, :ended}

      {:ok, %{status: 404} = res} ->
        if (Http.json(res) || %{})["error"] == "session_not_found", do: {:ok, :not_found}, else: {:error, oauth_failure(res)}

      {:ok, res} ->
        {:error, oauth_failure(res)}

      {:error, _} = e ->
        e
    end
  end

  @doc """
  Record that your app session `app_session_id` is backed by the Atlas `sid`, until `expires_at`
  (epoch ms or `DateTime`). Call it when you create your app session. Needs `:sid_store`.
  """
  @spec bind_session(t(), String.t(), String.t(), integer() | DateTime.t()) :: :ok
  def bind_session(%__MODULE__{sid_store: nil}, _sid, _id, _exp), do: raise(ArgumentError, "bind_session: `:sid_store` is not configured.")

  def bind_session(%__MODULE__{sid_store: store}, sid, app_session_id, expires_at)
      when is_binary(sid) and sid != "" and is_binary(app_session_id) and app_session_id != "",
      do: AtlasAuth.RP.SidStore.bind(store, sid, app_session_id, expires_at)

  @doc """
  The `on_logout` function for `AtlasAuth.Plug.BackchannelLogout`: takes the app sessions bound to the
  token's `sid` out of the `:sid_store`, passes them to `fun.(app_session_ids, claims)` and, if `fun`
  returns `{:error, _}` or raises, puts the bindings back so Atlas's retry finds them.
  """
  @spec backchannel_handler(t(), (list(String.t()), map() -> any())) :: (map() -> any())
  def backchannel_handler(%__MODULE__{} = rp, fun) when is_function(fun, 2) do
    fn claims ->
      ids = if claims.sid && rp.sid_store, do: AtlasAuth.RP.SidStore.take(rp.sid_store, claims.sid), else: []

      restore = fn ->
        for id <- ids, do: AtlasAuth.RP.SidStore.bind(rp.sid_store, claims.sid, id, now_ms(rp) + 86_400_000)
      end

      try do
        case fun.(ids, claims) do
          {:error, _} = e ->
            restore.()
            e

          other ->
            other
        end
      rescue
        e ->
          restore.()
          reraise e, __STACKTRACE__
      end
    end
  end

  @doc """
  Sign-out: with a `:sid` and a `:secret_key`, revokes the Atlas session server-side first, then
  `{:ok, %{location:, cookies:}}` 302s the browser to `/oauth2/logout`. With `server_sign_out: true`,
  one call ends this app's grants and the Atlas session and the redirect goes straight to the post-logout
  URI. End your own session (clear your cookie on this response) as well.

  Options: `:id_token` (lets Atlas end the session without asking), `:sid`, `:post_logout_redirect_uri`,
  `:state`, `:set_cookies` (`Set-Cookie` values to send on the redirect).
  """
  @spec sign_out(t(), keyword()) :: {:ok, %{location: String.t(), cookies: [String.t()]}} | {:error, term()}
  def sign_out(%__MODULE__{} = rp, opts \\ []) do
    sid = opts[:sid]

    if rp.server_sign_out and is_binary(sid) and sid != "" and rp.secret_key not in [nil, ""] do
      url = api(rp) <> "/v1/oauth_clients/" <> URI.encode(rp.client_id, &URI.char_unreserved?/1) <> "/logout"
      headers = [{"authorization", "Bearer " <> rp.secret_key}, {"accept", "application/json"}, {"content-type", "application/json"}]

      case Http.request(:post, url, headers, Jason.encode!(%{sid: sid}), http(rp)) do
        {:ok, %{status: s}} when s in 200..299 or s == 404 ->
          # 404: this instance has no such session any more, so there is nothing left to end.
          target = opts[:post_logout_redirect_uri] || rp.post_logout_redirect_uri || "/"
          target = if opts[:state], do: add_state(target, opts[:state]), else: target
          {:ok, %{location: target, cookies: opts[:set_cookies] || []}}

        {:ok, res} ->
          {:error, api_failure(res)}

        {:error, _} = e ->
          e
      end
    else
      with {:ok, _} <- maybe_revoke(rp, sid),
           {:ok, url} <-
             OIDC.logout_url(
               oidc_base(rp) ++
                 [
                   post_logout_redirect_uri: opts[:post_logout_redirect_uri] || rp.post_logout_redirect_uri,
                   id_token_hint: opts[:id_token],
                   state: opts[:state]
                 ]
             ) do
        {:ok, %{location: url, cookies: opts[:set_cookies] || []}}
      end
    end
  end

  # -- internals ------------------------------------------------------------------------

  defp maybe_revoke(rp, sid) do
    if rp.secret_key not in [nil, ""] and is_binary(sid) and sid != "", do: revoke_session(rp, sid), else: {:ok, :skipped}
  end

  defp oidc_base(rp) do
    [
      issuer: rp.issuer,
      client_id: rp.client_id,
      redirect_uri: rp.redirect_uri,
      secret: rp.secret,
      cookie_name: rp.cookie_name,
      http: rp.http,
      now_ms: rp.now_ms,
      fetcher: rp.fetcher
    ]
  end

  defp session_call(rp, sid, action) do
    cond do
      rp.secret_key in [nil, ""] ->
        raise ArgumentError, "#{if action == "touch", do: "touch_if_due", else: "revoke_session"}: `:secret_key` is not configured."

      not (is_binary(sid) and sid != "") ->
        raise ArgumentError, "A session id (`sid`) is required."

      true ->
        url = api(rp) <> "/v1/sessions/" <> URI.encode(sid, &URI.char_unreserved?/1) <> "/" <> action
        Http.request(:post, url, [{"authorization", "Bearer " <> rp.secret_key}, {"accept", "application/json"}], nil, http(rp))
    end
  end

  # The app's own sign-in, authenticated like the token endpoint (`/oauth2/session/touch` or `/end`).
  defp app_session_call(rp, sid, action) do
    method = rp.client_auth || if(rp.client_secret, do: :client_secret_basic, else: :none)

    if method == :none or rp.client_secret in [nil, ""] do
      raise ArgumentError, "configure `:client_secret` (the app's client credentials)#{if action == "touch", do: " or `:secret_key`", else: ""}; a public client cannot call it."
    end

    if not (is_binary(sid) and sid != ""), do: raise(ArgumentError, "A session id (`sid`) is required.")
    base = [{"content-type", "application/x-www-form-urlencoded"}, {"accept", "application/json"}]

    {headers, form} =
      if method == :client_secret_basic do
        # RFC 6749 2.3.1: both halves are form-encoded before Basic encoding.
        auth = "Basic " <> Base.encode64(URI.encode_www_form(rp.client_id) <> ":" <> URI.encode_www_form(rp.client_secret))
        {[{"authorization", auth} | base], [{"sid", sid}]}
      else
        {base, [{"sid", sid}, {"client_id", rp.client_id}, {"client_secret", rp.client_secret}]}
      end

    Http.request(:post, String.replace(rp.issuer, ~r/\/+\z/, "") <> "/oauth2/session/" <> action, headers, URI.encode_query(form), http(rp))
  end

  defp oauth_failure(%{status: status} = res) do
    body = Http.json(res) || %{}
    %{status: status, code: body["error"] || "request_failed", message: body["error_description"] || "The issuer answered #{status}."}
  end

  defp api_failure(%{status: status} = res) do
    errors = (Http.json(res) || %{})["errors"]
    first = if is_list(errors), do: List.first(errors) || %{}, else: %{}
    %{status: status, code: first["code"], message: first["message"] || "The Atlas API answered #{status}."}
  end

  defp error_code(res) do
    case (Http.json(res) || %{})["errors"] do
      [%{"code" => c} | _] -> c
      _ -> nil
    end
  end

  defp add_state(target, state) do
    uri = URI.parse(target)
    q = URI.decode_query(uri.query || "") |> Map.put("state", state)
    URI.to_string(%{uri | query: URI.encode_query(q)})
  end

  defp api(rp), do: String.replace(rp.api_url || @default_api, ~r/\/+\z/, "")
  defp http(rp), do: if(rp.http, do: [http: rp.http], else: [])
  defp now_ms(rp), do: rp.now_ms || System.system_time(:millisecond)
  defp put_if(map, _k, nil), do: map
  defp put_if(map, k, v), do: Map.put(map, k, v)
  defp stringify(m), do: for({k, v} <- m || %{}, into: %{}, do: {to_string(k), v})
end

defmodule AtlasAuth.RP.SidStore do
  @moduledoc """
  Maps an Atlas `sid` (the `sid` claim of the ID token) to the session ids of YOUR app, so a
  back-channel logout that names only the `sid` can end exactly the app sessions it backs.

  Bind when you create your app session (after MFA, if you gate on it): a step-up callback
  carries the same `sid`, so there is nothing new to bind unless you rotate your own session
  id then. A store is a module implementing this behaviour, or `{module, state}`; the built-in
  `AtlasAuth.RP.SidStore.Memory` is an in-process store (one node: use a shared one, such as a
  database table, when you run several).
  """

  @callback bind(state :: term(), sid :: String.t(), app_session_id :: String.t(), expires_at_ms :: integer()) :: :ok
  @callback take(state :: term(), sid :: String.t()) :: [String.t()]

  @doc false
  def bind({mod, state}, sid, id, exp), do: mod.bind(state, sid, id, ms(exp))
  def bind(mod, sid, id, exp) when is_atom(mod), do: mod.bind(nil, sid, id, ms(exp))

  @doc false
  def take({mod, state}, sid), do: mod.take(state, sid)
  def take(mod, sid) when is_atom(mod), do: mod.take(nil, sid)

  defp ms(%DateTime{} = d), do: DateTime.to_unix(d, :millisecond)
  defp ms(n) when is_integer(n), do: n
end

defmodule AtlasAuth.RP.SidStore.Memory do
  @moduledoc """
  An in-process `AtlasAuth.RP.SidStore` on an Agent. Start it once and pass `{AtlasAuth.RP.SidStore.Memory, pid}`
  as `:sid_store`:

      {:ok, store} = AtlasAuth.RP.SidStore.Memory.start_link([])
      rp = AtlasAuth.RP.new(..., sid_store: {AtlasAuth.RP.SidStore.Memory, store})
  """
  @behaviour AtlasAuth.RP.SidStore

  @doc "Start the store. Option `:now_ms` is a clock function (tests)."
  def start_link(opts \\ []) do
    clock = opts[:now_ms] || fn -> System.system_time(:millisecond) end
    Agent.start_link(fn -> %{clock: clock, by_sid: %{}} end)
  end

  @impl true
  def bind(pid, sid, id, expires_at) do
    Agent.update(pid, fn %{clock: clock, by_sid: m} = s ->
      m = sweep(m, clock.())
      %{s | by_sid: Map.update(m, sid, %{id => expires_at}, &Map.put(&1, id, expires_at))}
    end)
  end

  @impl true
  def take(pid, sid) do
    Agent.get_and_update(pid, fn %{clock: clock, by_sid: m} = s ->
      m = sweep(m, clock.())
      {m |> Map.get(sid, %{}) |> Map.keys(), %{s | by_sid: Map.delete(m, sid)}}
    end)
  end

  defp sweep(m, now) do
    m
    |> Enum.map(fn {sid, apps} -> {sid, Map.reject(apps, fn {_, exp} -> exp <= now end)} end)
    |> Enum.reject(fn {_, apps} -> map_size(apps) == 0 end)
    |> Map.new()
  end
end
