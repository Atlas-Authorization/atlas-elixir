# Changelog

All notable changes to `atlas_auth` are documented here.

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
