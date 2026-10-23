# Changelog

All notable changes to `atlas_auth` are documented here.

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
