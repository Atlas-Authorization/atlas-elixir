defmodule AtlasAuth.BetterAuth do
  @moduledoc """
  Moving from Better Auth to Atlas without signing anyone out.

  During the migration window a returning user still carries their Better Auth
  session cookie (`better-auth.session_token`, `__Secure-` prefixed over https). It
  is HttpOnly, so only your server can read it. The bridge reads it, exchanges it
  ONCE with Atlas through the Backend API (`POST /v1/migrations/better_auth/exchange`,
  with the instance secret key, forwarding the end user's IP and user agent), sets
  the Atlas session as your own first-party cookies and clears the Better Auth
  cookies. Atlas finds the session in your import (or asks your old app, with the
  live fallback on) and runs the normal sign-in path on it — MFA policy included: a
  user who still owes a second factor is sent to finish it.

  `decide/2` is framework-neutral; `AtlasAuth.Plug.BetterAuthBridge` (or the
  `:better_auth_bridge` option of `AtlasAuth.Plug`) renders it for Plug/Phoenix.

  Options shared by `exchange/2`, `exchange_session/2` and `decide/2`:

    * `:secret_key` — the instance secret key (falls back to
      `config :atlas_auth, :secret_key`, then `ATLAS_SECRET_KEY`).
    * `:api_url` — the Backend API origin (default `https://api.atlasauth.net`).
    * `:client_ip` / `:user_agent` — the END USER's, sent as `X-Atlas-Client-IP` /
      `X-Atlas-Client-User-Agent` so guards, risk and geo checks see the user.
    * `:remember` — `false` records a browser-session session.
    * `:poster` — `(url, headers, body -> {:ok, status, body} | {:error, term})`,
      default `:httpc` (tests inject their own).

  Bridge settings (enabling the bridge, the window, the live fallback) and the bundle
  import are Backend API resources this verifier-only SDK has no client for: use the
  dashboard, the Atlas CLI, another server SDK or Terraform (`atlas_better_auth_bridge`).
  """

  @prefix "better-auth"
  @exchange_path "/v1/migrations/better_auth/exchange"
  @default_api_url "https://api.atlasauth.net"
  @outcomes %{
    "closed" => :closed,
    "invalid" => :invalid,
    "signature_invalid" => :signature_invalid,
    "expired" => :expired,
    "reused" => :reused,
    "user_unavailable" => :user_unavailable,
    "rate_limited" => :rate_limited
  }
  @final ~w(invalid signature_invalid expired reused user_unavailable)a

  @type refusal ::
          :closed
          | :invalid
          | :signature_invalid
          | :expired
          | :reused
          | :user_unavailable
          | :rate_limited
          | :unavailable

  @type result ::
          {:session,
           %{
             jwt: String.t(),
             refresh_token: String.t(),
             session_id: String.t(),
             user_id: String.t(),
             expires_in: integer()
           }}
          | {:needs_mfa, %{attempt_id: String.t(), status: String.t()}}
          | {:refused, refusal(), non_neg_integer()}

  @doc "Better Auth's default cookie prefix (`advanced.cookiePrefix`)."
  def cookie_prefix, do: @prefix

  @doc "The Backend API path of the secret-key exchange."
  def exchange_path, do: @exchange_path

  @doc """
  The Better Auth cookie names for `prefix`: `session_token` (the `__Secure-` name
  first) and `all` (every cookie the bridge clears).
  """
  @spec cookie_names(String.t()) :: %{session_token: [String.t()], all: [String.t()]}
  def cookie_names(prefix \\ @prefix) do
    base = Enum.map(~w(session_token session_data account_data dont_remember), &"#{prefix}.#{&1}")

    %{
      session_token: ["__Secure-#{prefix}.session_token", "#{prefix}.session_token"],
      all: Enum.map(base, &("__Secure-" <> &1)) ++ base
    }
  end

  @doc """
  The raw Better Auth session cookie value from a `Cookie` header (or a cookie map),
  the `__Secure-` name first; `nil` when absent. `:cookie_name` overrides the name
  when the old app set `advanced.cookies.session_token.name`.
  """
  @spec read_session_cookie(String.t() | map() | nil, keyword()) :: String.t() | nil
  def read_session_cookie(cookies, opts \\ []) do
    jar = jar(cookies)

    names =
      case opts[:cookie_name] do
        name when is_binary(name) and name != "" -> ["__Secure-" <> name, name]
        _ -> cookie_names(opts[:cookie_prefix] || @prefix).session_token
      end

    Enum.find_value(names, fn n ->
      case Map.get(jar, n) do
        v when is_binary(v) and v != "" -> v
        _ -> nil
      end
    end)
  end

  defp jar(nil), do: %{}
  defp jar(map) when is_map(map), do: map

  defp jar(header) when is_binary(header) do
    header
    |> String.split(";")
    |> Enum.reduce(%{}, fn part, acc ->
      case String.split(String.trim(part), "=", parts: 2) do
        [k, v] when k != "" -> Map.put_new(acc, k, v)
        _ -> acc
      end
    end)
  end

  @doc """
  Exchange a Better Auth session (the raw cookie value or the bare token) for an
  Atlas session, once. `{:ok, body}` is `session_tokens` or, when a second factor is
  owed, a `sign_in_attempt`; a refusal is
  `{:error, %{status:, code:, message:, meta:}}` (`meta["bridge_outcome"]` says why),
  and `{:error, reason}` a transport failure. Never retried: the token is single
  use. See `exchange_session/2` for a classified result.
  """
  @spec exchange(String.t(), keyword()) :: {:ok, map()} | {:error, map() | term()}
  def exchange(token, opts \\ []) do
    secret = secret_key!(opts)
    base = opts |> Keyword.get(:api_url, @default_api_url) |> String.trim_trailing("/")
    poster = Keyword.get(opts, :poster, &AtlasAuth.Introspection.default_post/3)

    headers =
      [
        {"content-type", "application/json"},
        {"authorization", "Bearer " <> secret},
        {"accept", "application/json"}
      ] ++
        present("x-atlas-client-ip", opts[:client_ip]) ++
        present("x-atlas-client-user-agent", opts[:user_agent])

    body =
      if opts[:remember] == false, do: %{token: token, remember: false}, else: %{token: token}

    case poster.(base <> @exchange_path, headers, Jason.encode!(body)) do
      {:ok, status, raw} when status in 200..299 ->
        case Jason.decode(raw) do
          {:ok, map} when is_map(map) -> {:ok, map}
          _ -> {:ok, %{}}
        end

      {:ok, status, raw} ->
        item =
          case Jason.decode(raw || "") do
            {:ok, %{"errors" => [first | _]}} when is_map(first) -> first
            _ -> %{}
          end

        {:error,
         %{
           status: status,
           code: item["code"] || "UNKNOWN",
           message: item["message"] || "",
           meta: if(is_map(item["meta"]), do: item["meta"], else: %{})
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp present(_name, v) when v in [nil, ""], do: []
  defp present(name, v), do: [{name, to_string(v)}]

  defp secret_key!(opts) do
    case opts[:secret_key] || Application.get_env(:atlas_auth, :secret_key) ||
           System.get_env("ATLAS_SECRET_KEY") do
      key when is_binary(key) and key != "" ->
        key

      _ ->
        raise ArgumentError,
              "AtlasAuth.BetterAuth needs :secret_key (or ATLAS_SECRET_KEY): the exchange goes " <>
                "through the Backend API with the instance secret key."
    end
  end

  @doc """
  `exchange/2`, classified. Never raises on a refusal or a transport failure:
  `{:refused, :unavailable, 0}` means try again on a later request.
  """
  @spec exchange_session(String.t(), keyword()) :: result()
  def exchange_session(token, opts \\ []) do
    case exchange(token, opts) do
      {:ok, %{"object" => "session_tokens", "jwt" => jwt, "refresh_token" => rt} = d}
      when is_binary(jwt) and jwt != "" and is_binary(rt) and rt != "" ->
        {:session,
         %{
           jwt: jwt,
           refresh_token: rt,
           session_id: d["session_id"] || "",
           user_id: d["user_id"] || "",
           expires_in: if(is_integer(d["expires_in"]), do: d["expires_in"], else: 0)
         }}

      {:ok, %{"object" => "sign_in_attempt", "id" => id, "status" => status}}
      when is_binary(id) and id != "" and
             status in ["needs_second_factor", "needs_mfa_enrollment"] ->
        {:needs_mfa, %{attempt_id: id, status: status}}

      {:ok, _} ->
        {:refused, :unavailable, 200}

      {:error, %{status: 429}} ->
        {:refused, :rate_limited, 429}

      {:error, %{status: status, meta: meta}} ->
        # Anything else (a 5xx, a guard refusal) is not a verdict on the Better
        # Auth session: keep it and retry later.
        {:refused, Map.get(@outcomes, meta["bridge_outcome"], :unavailable), status}

      {:error, _} ->
        {:refused, :unavailable, 0}
    end
  end

  @doc "True for refusals after which the Better Auth session will never exchange."
  @spec final?(refusal()) :: boolean()
  def final?(outcome), do: outcome in @final

  @doc """
  Decide for one request. `cookies` is the `Cookie` header (or a cookie map). Returns
  `%{action:, cookies:, session:, attempt_id:, status:, outcome:}`:

    * `:none` — no Better Auth cookie, or an Atlas session (`__session` /
      `__atlas_rt`) is already present. No network call.
    * `:signed_in` — set `cookies` and re-enter (redirect to the same URL).
    * `:needs_mfa` — redirect to `continuation_url/3` of your sign-in page;
      `cookies` clears the spent Better Auth cookies.
    * `:refused` — carry on; `cookies` clears the Better Auth cookies only when the
      refusal is final.

  Options: those of `exchange/2` plus `:cookie_prefix`, `:cookie_name`,
  `:cookie_domain` (the domain the Better Auth cookies were set on) and `:secure`
  (mark the Atlas cookies Secure; default true).
  """
  @spec decide(String.t() | map() | nil, keyword()) :: map()
  def decide(cookies, opts \\ []) do
    jar = jar(cookies)
    token = read_session_cookie(jar, opts)
    atlas? = present?(jar["__session"]) or present?(jar["__atlas_rt"])

    if token == nil or atlas? do
      decision(:none)
    else
      decision_for(exchange_session(token, opts), opts)
    end
  end

  defp present?(v), do: is_binary(v) and v != ""

  defp decision(action, fields \\ %{}) do
    Map.merge(
      %{action: action, cookies: [], session: nil, attempt_id: nil, status: nil, outcome: nil},
      fields
    )
  end

  @doc "The decision for an `exchange_session/2` result (what `decide/2` returns)."
  @spec decision_for(result(), keyword()) :: map()
  def decision_for(result, opts \\ []) do
    secure = Keyword.get(opts, :secure, true) != false

    case result do
      {:session, s} ->
        decision(:signed_in, %{
          session: s,
          cookies:
            [
              cookie("__session", s.jwt, same_site: "Lax", secure: secure),
              cookie("__atlas_rt", s.refresh_token,
                http_only: true,
                same_site: "Lax",
                secure: secure
              )
            ] ++ clear_cookies(opts)
        })

      {:needs_mfa, %{attempt_id: id, status: status}} ->
        decision(:needs_mfa, %{attempt_id: id, status: status, cookies: clear_cookies(opts)})

      {:refused, outcome, _status} ->
        decision(:refused, %{
          outcome: outcome,
          cookies: if(final?(outcome), do: clear_cookies(opts), else: [])
        })
    end
  end

  @doc "True when the request should be answered with a redirect carrying the cookies."
  def redirect?(%{action: :none}), do: false
  def redirect?(%{action: :refused, cookies: []}), do: false
  def redirect?(%{}), do: true

  defp cookie(name, value, attrs) do
    Map.merge(
      %{
        name: name,
        value: value,
        path: "/",
        domain: nil,
        http_only: false,
        same_site: nil,
        secure: false,
        max_age: nil
      },
      Map.new(attrs)
    )
  end

  defp clear_cookies(opts) do
    names = cookie_names(opts[:cookie_prefix] || @prefix).all

    names =
      case opts[:cookie_name] do
        n when is_binary(n) and n != "" -> names ++ [n, "__Secure-" <> n]
        _ -> names
      end

    # A `__Secure-` cookie can only be overwritten by a Secure Set-Cookie.
    Enum.map(names, fn n ->
      cookie(n, "",
        max_age: 0,
        domain: opts[:cookie_domain],
        secure: String.starts_with?(n, "__Secure-")
      )
    end)
  end

  @doc "A bridge cookie as a `Set-Cookie` header value."
  @spec serialize_cookie(map()) :: String.t()
  def serialize_cookie(c) do
    [
      "#{c.name}=#{c.value}",
      "Path=#{c.path || "/"}",
      c.domain && "Domain=#{c.domain}",
      c.max_age != nil && "Max-Age=#{c.max_age}",
      c.max_age == 0 && "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
      c.http_only && "HttpOnly",
      c.secure && "Secure",
      c.same_site && "SameSite=#{c.same_site}"
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.join("; ")
  end

  @doc """
  `url` with `__atlas_attempt` / `__atlas_status` set (for `:needs_mfa`); earlier
  values of those two are replaced, the rest of the URL is kept.
  """
  @spec continuation_url(String.t(), String.t(), String.t()) :: String.t()
  def continuation_url(url, attempt_id, status) do
    {before_hash, hash} =
      case String.split(url, "#", parts: 2) do
        [a, h] -> {a, "#" <> h}
        [a] -> {a, ""}
      end

    {base, query} =
      case String.split(before_hash, "?", parts: 2) do
        [b, q] -> {b, q}
        [b] -> {b, ""}
      end

    kept =
      query
      |> String.split("&", trim: true)
      |> Enum.reject(fn pair ->
        (pair |> String.split("=", parts: 2) |> hd()) in ["__atlas_attempt", "__atlas_status"]
      end)

    added = [
      "__atlas_attempt=" <> URI.encode_www_form(attempt_id),
      "__atlas_status=" <> URI.encode_www_form(status)
    ]

    base <> "?" <> Enum.join(kept ++ added, "&") <> hash
  end

  @doc """
  The end user's IP from proxy headers: the first `X-Forwarded-For` hop, else
  `X-Real-IP`; `nil` when neither is set. Only as trustworthy as your proxy.
  """
  @spec client_ip_from_headers(list() | map()) :: String.t() | nil
  def client_ip_from_headers(headers) do
    get = fn name ->
      Enum.find_value(headers, fn
        {k, v} -> if String.downcase(to_string(k)) == name, do: to_string(v)
        _ -> nil
      end)
    end

    xff = (get.("x-forwarded-for") || "") |> String.split(",") |> hd() |> String.trim()
    real = (get.("x-real-ip") || "") |> String.trim()

    cond do
      xff != "" -> xff
      real != "" -> real
      true -> nil
    end
  end
end
