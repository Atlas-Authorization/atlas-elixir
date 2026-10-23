# atlas_auth

The official **Elixir** backend SDK for **Atlas** — local RS256 session-token
verification against the instance JWKS, with a **Plug/Phoenix** integration. It
is the Elixir peer of the Go, PHP, Rust and other Atlas server SDKs: the same
verification rules, the same coarse failure reasons, the same §13.1
token-confusion guard.

- **Local verification, no hot-path network call.** Signatures are checked
  against a cached JWKS. A customer API handling thousands of requests a second
  cannot make an outbound call per request, and one that did would make Atlas's
  availability its own. The revocation window is bounded instead by the short
  token lifetime.
- **JWKS cached in-process, keyed by URL,** with a kid-miss refetch at most once
  a minute — so key rotation needs no deploy, and a flood of random `kid`s cannot
  turn your app into a traffic amplifier aimed at the JWKS endpoint.
- **RS256 pinned.** `alg: none` and key-confusion attacks never verify.
- **Plug is an optional dependency.** Want only the verifier? You never pull Plug
  in. The plugs work in any Plug or Phoenix app.

## Install

```elixir
# mix.exs
def deps do
  [
    {:atlas_auth, "~> 0.2"}
  ]
end
```

Requires Elixir ~> 1.14. Pulls in `jose` (RS256/JWKS) and `jason` (JSON). `plug`
is optional — add it (most Phoenix apps already have it) to use the plugs.

## Phoenix / Plug

```elixir
# lib/my_app_web/router.ex
pipeline :api do
  plug :accepts, ["json"]

  plug AtlasAuth.Plug,
    jwks_url: "https://your-instance.atlas.example/.well-known/jwks.json",
    issuer: "https://your-instance.atlas.example"

  # Halt unauthenticated requests with 401. Omit it on pipelines that allow
  # anonymous access and read `conn.assigns.atlas_authenticated?` yourself.
  plug AtlasAuth.Plug.RequireAuth
end
```

`AtlasAuth.Plug` assigns on every request:

| assign | value |
| --- | --- |
| `:atlas_authenticated?` | `true` / `false` |
| `:atlas_claims` | `%AtlasAuth.Claims{}` or `nil` |
| `:atlas_error` | failure reason or `nil` |

In a controller:

```elixir
def index(conn, _params) do
  claims = conn.assigns.atlas_claims

  if AtlasAuth.Claims.has_permission?(claims, "billing:read") do
    json(conn, %{user: claims.sub, org: claims.org_id})
  else
    conn |> put_status(403) |> json(%{error: "forbidden"})
  end
end
```

## Verify a token directly

```elixir
{:ok, claims} =
  AtlasAuth.verify(token,
    jwks_url: "https://your-instance.atlas.example/.well-known/jwks.json",
    issuer: "https://your-instance.atlas.example")

claims.sub                                      # "user_..."
claims.org_role                                 # "admin"
AtlasAuth.Claims.has_role?(claims, "admin")     # true
AtlasAuth.Claims.has_permission?(claims, "billing:read")
```

`AtlasAuth.verify/2` returns `{:ok, %AtlasAuth.Claims{}}` or `{:error, reason}`,
where `reason` is one of:

| reason | meaning |
| --- | --- |
| `:malformed` | no token, or not a three-part JWT |
| `:invalid` | signature, issuer, expiry, algorithm, or the token-confusion guard |
| `:no_keys` | the JWKS was empty or unreachable |
| `:unauthorized_party` | `azp` not in the configured allowlist |

The reasons are deliberately coarse — telling a caller *which* check failed helps
someone refining a forged token more than it helps a developer.

## Configuration

Pass `:jwks_url` and `:issuer` as options, or set them globally:

```elixir
# config/runtime.exs
config :atlas_auth,
  jwks_url: System.fetch_env!("ATLAS_JWKS_URL"),
  issuer: System.fetch_env!("ATLAS_ISSUER")
```

They also fall back to the `ATLAS_JWKS_URL` / `ATLAS_ISSUER` environment
variables. Other options: `:authorized_parties` (an `azp` allowlist), `:leeway`
(clock skew in seconds, default `5`), and `:fetcher` (inject your own JWKS
fetcher — the default uses `:httpc`, no extra dependency).

## What it verifies

Matching the other Atlas SDKs, in order: a non-empty three-part JWT; a pinned
`RS256` header algorithm; an RS256 signature against the JWKS key whose `kid`
matches; `iss` equals the configured issuer; `exp`/`nbf`/`iat` within ~5s of
clock skew; the §13.1 token-confusion guard (reject any token carrying
`token_use` other than `"session"`, or an `aud` claim — an OP access/id token
must never replay as a customer session); and, when configured, an `azp`
allowlist check.

## Back-channel logout

If your app is registered with a back-channel logout URI, Atlas POSTs a signed
`logout_token` there when a user signs out (or their session is ended), so you
can end your own local session for them right away.

### With Plug / Phoenix

```elixir
# lib/my_app_web/router.ex
forward "/auth/backchannel-logout", AtlasAuth.Plug.BackchannelLogout,
  jwks_url: "https://your-instance.atlas.example/.well-known/jwks.json",
  issuer: "https://your-instance.atlas.example",
  client_id: "your-client-id",
  on_logout: &MyApp.Sessions.end_from_logout/1
```

```elixir
defmodule MyApp.Sessions do
  # claims = %{sub: "user_..." | nil, sid: "sess_..." | nil, jti: "...", iat: 1_700_000_000}
  def end_from_logout(%{sid: sid, sub: sub}) do
    cond do
      sid -> delete_sessions_by_atlas_sid(sid)  # just that session
      sub -> delete_sessions_by_atlas_user(sub) # every session of that user
    end

    :ok
  end
end
```

The plug answers `200` on success, `400` when the token is missing or invalid,
and `501` if `on_logout` returns `{:error, reason}` — always with
`Cache-Control: no-store`. It only accepts `POST`.

### Any framework

```elixir
# body = the raw request body (application/x-www-form-urlencoded)
token = URI.decode_query(body)["logout_token"]

case AtlasAuth.verify_logout_token(token,
       jwks_url: "https://your-instance.atlas.example/.well-known/jwks.json",
       issuer: "https://your-instance.atlas.example",
       client_id: "your-client-id") do
  {:ok, %{sid: sid, sub: sub}} ->
    # End the matching local session(s): by sid if present, else every session for sub.
    end_sessions(sid: sid, sub: sub)
    respond(200, headers: [{"cache-control", "no-store"}])

  {:error, _reason} ->
    respond(400, headers: [{"cache-control", "no-store"}])
end
```

The verifier checks: RS256 signature against your instance keys, `typ` is
`logout+jwt` (when present), `iss` matches, `aud` contains your client id, `iat`
is present and not in the future, `exp` (when present) has not passed, `jti` is
present, `events` contains `http://schemas.openid.net/event/backchannel-logout`
with an object value, `sid` and/or `sub` is present, and there is no `nonce`.
`:client_id` can also come from `config :atlas_auth, client_id: ...` or
`ATLAS_CLIENT_ID`.

**Replay protection.** Each logout token has a unique `jti`. Remember the `jti`
of every token you accept (until its `exp`, or a few minutes) in a store all your
app instances share — Redis, your database, or ETS on a single node — and ignore
a token whose `jti` you have already seen. With the plug, do this check at the
top of your `on_logout` function and return `:ok` for a repeat.

## Webhooks

`AtlasAuth.Webhook.verify/4` checks the signature on events Atlas sends to your webhook endpoints. Verify the
raw body, before any JSON decode:

```elixir
case AtlasAuth.Webhook.verify(raw_body, conn.req_headers, secret) do
  {:ok, %{delivery_id: id, event: event}} -> handle(id, event)
  {:error, _reason} -> send_resp(conn, 400, "")
end
```

The `atlas-signature` header can carry several signatures separated by spaces (`v1,<sig> v1,<sig>`). While an
endpoint secret rotates, Atlas may sign each delivery with the old and the new secret; the delivery verifies
when any one signature matches.

## Policy acceptance

Terms of service and other policies are managed with the Backend API (another server SDK, the CLI or Terraform).
This SDK carries the pieces that run in your application:

* `AtlasAuth.Claims.pol(claims)` and `AtlasAuth.Claims.has_accepted_policy?(claims, "tos", "2026-10-24")` read the
  `pol` session claim (the accepted version of every required policy), when the instance turned it on.
* `AtlasAuth.Constants.webhook_user_policy_accepted()` and `webhook_policy_version_published()` name the two webhook events.
* To serve policy text from your own system, `AtlasAuth.PolicySource.verify_feed_request/1` checks Atlas's signed
  `GET {endpoint_url}/policies` request, and `AtlasAuth.PolicySource.sign_published/4` / `sign_retired/3` produce the
  signed body and headers to POST to the source's `webhook_url`.

```elixir
case AtlasAuth.PolicySource.verify_feed_request(
       method: conn.method,
       path_and_query: conn.request_path <> "?" <> conn.query_string,
       headers: conn.req_headers,
       secret: secret
     ) do
  {:ok, %{key: key}} -> json(conn, build_feed(key))
  {:error, _reason} -> send_resp(conn, 401, "")
end
```

## Migrate from Better Auth

**No forced logout.** With the session bridge turned on for your instance (dashboard,
Atlas CLI, a server SDK or the Terraform `atlas_better_auth_bridge` resource), put the
bridge in front of your pipeline. A returning user's Better Auth session cookie is
exchanged once — server to server with your secret key, forwarding the user's IP and
user agent — for the Atlas session cookies, and the browser is redirected (`307`) to
the same URL:

```elixir
plug AtlasAuth.Plug.BetterAuthBridge,
  secret_key: System.fetch_env!("ATLAS_SECRET_KEY"),
  sign_in_url: "/sign-in"   # where a user who still owes a second factor finishes

# or as an option of the session plug, which runs it first:
plug AtlasAuth.Plug, jwks_url: ..., issuer: ..., secret_key: ..., better_auth_bridge: [sign_in_url: "/sign-in"]
```

Options: `:cookie_prefix` (Better Auth's `advanced.cookiePrefix`), `:cookie_name`,
`:cookie_domain` (so the old cookies clear), `:secure`, `:trust_forwarded_for`. The
Better Auth cookies are cleared only when the refusal is final, so a closed bridge, a
429 or an outage retries on a later request. Outside Plug, use
`AtlasAuth.BetterAuth.decide/2`, or `AtlasAuth.BetterAuth.exchange_session/2` for the
classified exchange.

**Better Auth JWTs** your API clients still hold can be accepted until a cutover date:

```elixir
AtlasAuth.Verifier.verify(token,
  jwks_url: "...", issuer: "...",
  secret_key: System.fetch_env!("ATLAS_SECRET_KEY"),   # maps sub -> Atlas user via external_id
  legacy_issuers: [
    [issuer: "https://app.example.com", until: ~U[2026-12-31 00:00:00Z],
     jwks_url: "https://app.example.com/api/auth/jwks"]
  ]
)
```

The claims then carry `sub` (the Atlas id), `external_id` (the Better Auth id) and
`raw["legacy"]`. EdDSA, ES256, ES512, RS256 and PS256 are accepted; a token without
`exp` is refused. Importing the Better Auth data and the bridge settings are Backend
API resources; this verifier-only SDK has no client for them.

## License

MIT. See [LICENSE](LICENSE).
