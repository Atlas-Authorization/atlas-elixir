# Changelog

All notable changes to `atlas_auth` are documented here.

## 0.10.0 — 2026-10-24

### Added

- **Enterprise SSO claims.** `AtlasAuth.Claims` gains `sso_organization_id` (the Atlas organization that owns the SSO connection, `nil` for an instance-wide one, independent of `org_id`) and `sso_connection_type` (`"saml"` | `"oidc"`, anything else is `nil`), read from verified session, ID-token and userinfo claims. Scope a per-organization "require SSO" rule on `sso_organization_id`, never on "signed in via SSO".

This package has no Backend API client, so the app adoption, preflight, dry-run and sealed-secret surfaces do not apply to it.

## 0.9.0 — 2026-10-24

### Added

- **Key formats.** `AtlasAuth.KeyFormat` (`parse/1`, `secret_key?/1`, `platform_key?/1`, `publishable_key?/1`, `webhook_secret?/1`, `partner_link_secret?/1`, `access_token?/1`) accepts the suite format `atlas_<live|test>_<kind>_...` alongside `sk_` / `pk_` / `psk_` / `whsec_` / `dsk_`. Webhook verification is unchanged: the whole secret string is the HMAC key.
- **Webhook signature v2.** `AtlasAuth.Webhook.verify_url/5` verifies deliveries from endpoints with `signature_versions` including `v2` (HMAC-SHA256 over `id.timestamp.url.body`, so a captured delivery cannot be replayed to another URL). It accepts any matching `v1` or `v2` entry, ignores unknown versions and takes `require_v2: true`. `verify/4` is unchanged and still ignores `v2` entries.
- **Event names.** `AtlasAuth.WebhookEvents`: the deprecated-alias table (`aliases/0`, `deprecated?/1`, `canonical/1`, `spellings/1`) and constants for the endpoint-health, delivery-target, secret-key (`secret_key.expiring` / `secret_key.revoked`), status-incident (`status.incident.*`), `webhook.test` and privacy (`privacy_request.updated` / `.completed`, `user.deletion_scheduled` / `.canceled`) events.
- **Data-rights receiver.** `AtlasAuth.Privacy.verify_call/4` verifies the signed case calls Atlas makes to an orchestrator and the `privacy_request.*` events, returns the delivery id (the `Idempotency-Key`), the body, the event and the `traceparent`; `request_from_event/1`, request types, statuses and the `privacy:execute` / `privacy:grants:revoke` scopes.
- **Trace context.** `AtlasAuth.Trace`: `new/0`, `parse/1`, `from_headers/1` for the W3C `traceparent` header.
- **Errors.** `AtlasAuth.Errors`: `INSUFFICIENT_SCOPE` (the former `SCOPE_MISSING` is still tolerated by `insufficient_scope?/1`), `STEP_UP_REQUIRED`, `ROUTE_NOT_FOUND`, `NOT_A_LIVE_INSTANCE`, `TEST_MODE_ONLY`, `TESTING_UNAVAILABLE`, `PARTNER_LINK_UNAVAILABLE`, `ORIGIN_NOT_ALLOWED`, and `parse/1` for an error body (`required_scope`, `did_you_mean`, `allowed_methods`, `docs_url`).
- **Claims.** `%AtlasAuth.Claims{}` gains `orgs` and `sso_connection_id` / `sso_tenant_id` / `sso_issuer` / `sso_domain`. `AtlasAuth.Constants`: `webhooks:reveal` scope, webhook signature versions, event naming modes, destination types and the referral provider id `referalli` (`referally` accepted as the former spelling).

### Not included

- The Backend API resources of this release (secret keys, whoami, partner links, token exchange, integrations, privacy executor client, webhook endpoint health / replay / destinations, status, audit exports, notices, advisories and the rest) need a Backend API client, which this verifier-only SDK does not have; use another server SDK, the CLI or Terraform.
- Opening a sealed secret (`secretRecipient`) needs a libsodium `crypto_box_seal_open`, which OTP `:crypto` does not provide; no dependency was added for it.

## 0.8.0 — 2026-10-24

### Added

- **Policy source protocol helpers.** `AtlasAuth.PolicySource.verify_feed_request/1` checks Atlas's signed `GET {endpoint_url}/policies` (`atlas-signature` `v1,<base64 HMAC-SHA256>` over `{id}.{timestamp}.GET\n{path+query}`, millisecond timestamps, several `v1` values accepted, 5-minute window; the result carries the `key` query parameter), and `sign_published/4` / `sign_retired/3` / `sign_event/2` / `sign_body/2` sign `policy.published` / `policy.retired` events for Atlas (Atlas-style headers). Cross-checked against the TypeScript reference vectors.
- `AtlasAuth.Claims.pol/1` and `has_accepted_policy?/3` read the `pol` claim. `AtlasAuth.Constants.webhook_user_policy_accepted/0` (`user.policy_accepted`) and `webhook_policy_version_published/0` (`policy.version_published`).
- The policy resources (`/v1/policies`, `policy_source`, `policy_settings`, a user's standing) are Backend API resources; this verifier-only SDK has no Backend API client, so they are not part of it (use the dashboard, the CLI, another server SDK or Terraform).

## 0.7.0 — 2026-10-24

### Added

- **Better Auth session bridge.** `AtlasAuth.Plug.BetterAuthBridge` (and the `better_auth_bridge:` option of `AtlasAuth.Plug`, which runs it first): a `GET` / `HEAD` carrying a Better Auth session cookie is exchanged once through the Backend API (`POST /v1/migrations/better_auth/exchange`, secret key, forwarding the end user's IP and user agent as `X-Atlas-Client-IP` / `X-Atlas-Client-User-Agent`) and answered with a `307` to the same URL, the Atlas session cookies set and the Better Auth cookies cleared; a user who still owes a second factor goes to `:sign_in_url` with `__atlas_attempt` / `__atlas_status`. `AtlasAuth.BetterAuth`: `exchange/2`, the classified `exchange_session/2` (`{:session, _}`, `{:needs_mfa, _}`, `{:refused, outcome, status}`), the framework-neutral `decide/2`, `cookie_names/1`, `read_session_cookie/2`, `serialize_cookie/1`, `continuation_url/3`, `client_ip_from_headers/1`. Better Auth cookies are cleared only on final refusals.
- **Better Auth JWTs during the cutover.** `AtlasAuth.Verifier.verify/2` (and so `AtlasAuth.Plug`) takes `legacy_issuers:`: a token whose `iss` is an old issuer, inside its `:until` window, is verified against that issuer's own keys only (`:jwks` or `:jwks_url`, cached like the Atlas JWKS), must carry `exp`, and has its `sub` mapped to the Atlas user — by `:resolve_subject`, or by an `external_id` lookup through the Backend API with `:secret_key` (cached five minutes in a supervised ETS table, `AtlasAuth.LegacyIssuers`). EdDSA, ES256, ES512, RS256 and PS256. `%AtlasAuth.Claims{}` gains `external_id`; `raw["legacy"]` names the old issuer and subject.
- The bundle import and the bridge settings are Backend API resources; this verifier-only SDK has no Backend API client, so they are not part of it (use the dashboard, the CLI, another server SDK or Terraform).

## 0.6.0 — 2026-10-24

### Added

- **DPoP (RFC 9449) on the access-token verifier.** A DPoP-bound token (`cnf.jkt`) is
  accepted only with the DPoP scheme and a valid proof (never as Bearer): `typ` `dpop+jwt`,
  `AtlasAuth.DPoP.algs/0` (ES256/384/512, RS256/384/512, PS256/384/512, EdDSA), public
  embedded JWK, signature, `htm`, normalised `htu` (`AtlasAuth.DPoP.normalize_htu/1`;
  `:public_origin` for path-only URLs), `iat` window, `ath`, `jti` replay via an
  `AtlasAuth.DPoP.ReplayStore` (`AtlasAuth.DPoP.MemoryReplayStore`, an ETS table under the
  application, by default; or a 2-arity function), RFC 7638 `AtlasAuth.DPoP.jwk_thumbprint/1`
  match. `:require_dpop` refuses unbound tokens; `:dpop_nonces`
  (`AtlasAuth.DPoP.HmacNonce.new/2`) demands a server nonce (`use_dpop_nonce`, `dpop_nonce` in
  the result for the `DPoP-Nonce` header). `verify/2` takes `:method`, `:url`, `:dpop`;
  results carry `dpop_bound`. Challenges use the `DPoP` scheme with `algs`.
  `AtlasAuth.Plug.RequireAccessToken` checks the proof against the conn and sets
  `dpop-nonce`. `protected_resource_metadata/4` advertises
  `dpop_signing_alg_values_supported` and takes `dpop_bound_access_tokens_required: true`.
- **Opaque access tokens.** `AtlasAuth.AccessToken.verify/2` (and `AtlasAuth.Plug.RequireAccessToken`) take `introspection: [client_id:, client_secret:, ...]`: a token that is not a JWT is validated at Atlas's RFC 7662 endpoint with your API's client credentials, cached in a node-local ETS table by token hash (TTL, negative TTL, never past `exp`, bounded); `introspect_jwts: true` checks JWTs live too. `AtlasAuth.Introspection` (supervised by the application).
- **Vercel BotID attestations.** `AtlasAuth.BotId.create_attestation(secret, is_bot, opts)` signs a verdict in Atlas's `atlas_botid.v1` format.
- **Device sign-in approval.** `AtlasAuth.DeviceAuthorizations.lookup/2`, `approve/2`, `deny/2` call the Frontend API with a user's session token (`frontend_api:`, `session_token:`); `format_user_code/1`, `user_code_from_url/1`. A refusal is `{:error, %{status:, code:, message:}}` (`STEP_UP_REQUIRED` means re-authenticate first).
- `AtlasAuth.Constants`: captcha providers (incl. `captchafox`, `vercel_botid`), account-linking trust levels, billing providers (incl. `chargebee`, `autumn`, `commet`), signing-key providers, the `session.updated` and `user.reactivated` webhook types and the `account_reactivated` email template.

### Changed

- Without `introspection`, a token that is not a JWT is refused with "configure `introspection` to accept opaque tokens" instead of "malformed".

## 0.5.0 — 2026-10-23

- **ES256.** Session and logout-token verification accept ES256 as well as RS256
  (`AtlasAuth.Verifier.signing_algs/0`), and nothing else; the token's `kid` selects one key whose
  type fixes the algorithm (an RSA key verifies only RS256, a P-256 key only ES256).
- **App roles.** `AtlasAuth.Claims.has_app_role?/2` and `has_app_permission?/2` read the
  `app_roles` / `app_permissions` claims (no active organization needed).
- **Access-token verification for your API.** `AtlasAuth.AccessToken.verify/2` checks an
  Atlas-issued OAuth access token locally (issuer, expiry, `token_use`, audience, scopes) and
  returns the RFC 6750 / RFC 9728 `WWW-Authenticate` challenge on refusal; the
  `AtlasAuth.Plug.RequireAccessToken` plug; `build_www_authenticate/1`,
  `protected_resource_metadata/3`, `protected_resource_metadata_path/1`. DPoP-bound tokens are
  refused.

## 0.4.0

- **Webhooks, several signatures.** `AtlasAuth.Webhook.verify/4` accepts an `atlas-signature` header with
  several space-separated `v1,<signature>` entries and verifies when any one matches (each compared in
  constant time). This prepares for webhook secret rotation with an overlap. A single signature works as
  before.

## 0.3.0

- **Back-channel logout, retryable failures.** `AtlasAuth.BackchannelLogout.retryable?/1` is true for
  `:no_keys` (the issuer's keys could not be fetched). `AtlasAuth.Plug.BackchannelLogout` now answers
  `503` with `Retry-After: 30` for it (was `400`), so Atlas retries the delivery; every other failure is
  still `400`.
- **Webhook verification.** `AtlasAuth.Webhook.verify/4` returns
  `{:ok, %{event, delivery_id, timestamp}}` or `{:error, reason}` (`:missing_headers`,
  `:malformed_signature`, `:stale_timestamp`, `:signature_mismatch`). `delivery_id` is the signed
  `atlas-id` header, the same on every retry of one event: deduplicate on it.

## 0.2.0

- **Back-channel logout verification.** `AtlasAuth.BackchannelLogout.verify/2`
  (also `AtlasAuth.verify_logout_token/2`) verifies an OpenID Connect
  Back-Channel Logout `logout_token` against the same cached instance JWKS as
  session tokens: RS256 only, `typ` of `logout+jwt` when present, `iss`, `aud`
  containing your `:client_id`, `iat` present and not in the future, `exp` when
  present, `jti` present, the back-channel logout `events` member, `sid` and/or
  `sub`, and no `nonce`. Returns `{:ok, %{sub, sid, jti, iat}}` or
  `{:error, reason}` with the same coarse reasons as `AtlasAuth.verify/2`.
- **`AtlasAuth.Plug.BackchannelLogout`.** An optional Plug that serves the
  logout endpoint: reads the form-encoded `logout_token`, verifies it, calls your
  `:on_logout` function to end the matching sessions, and answers `200` (or
  `400` for a missing/invalid token, `501` when `:on_logout` returns
  `{:error, _}`), always with `Cache-Control: no-store`.
- New `:client_id` option (falls back to `config :atlas_auth, client_id:` and
  `ATLAS_CLIENT_ID`).

## 0.1.0

- Initial release: local RS256 session-token verification against a cached
  JWKS, `AtlasAuth.Plug` and `AtlasAuth.Plug.RequireAuth`.
