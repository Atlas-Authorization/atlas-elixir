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
    {:atlas_auth, "~> 0.1"}
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

## License

MIT. See [LICENSE](LICENSE).
