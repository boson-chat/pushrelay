# boson pushrelay

The push relay for the official Boson apps. It is an ordinary **Web Push service**
(RFC 8030) that installs' Ergo sends encrypted (RFC 8291 `aes128gcm`), VAPID-signed
(RFC 8292) pushes to, and it forwards them to **APNs** (iOS) and **FCM** (Android) with the
app's credentials. The relay never holds a decryption key: the body goes to the phone as
is, and only the phone can read it.

Design: [`docs/push.md` §2 in boson-chat/stack](https://github.com/boson-chat/stack/blob/main/docs/push.md).
Runs only at boson.chat (`https://push.boson.chat`), as the stack's `pushrelay` compose profile.

```
phone ── POST /v1/mailboxes (attested) ──► relay   (returns endpoint + secret)
phone ── WEBPUSH REGISTER <endpoint> ────► Ergo
Ergo  ── POST /v1/push/<id> (VAPID) ─────► relay ── APNs / FCM ──► phone decrypts
```

## API (public listener, `HTTP_ADDR`, default `:8080`)

Errors are JSON: `{"error": "<code>", "message": "...", "code": "<code>"}`; `429` and some
`503`s carry `Retry-After`.

### `GET /v1/challenge`
A single-use random challenge for attestation, valid for 5 minutes
(`PUSHRELAY_CHALLENGE_TTL`).
```json
{"challenge": "5Ufn-jWSZjLc...", "expires_at": "2026-11-27T14:05:53Z", "expires_in": 300}
```
Limited to 5 × `PUSHRELAY_CREATE_PER_IP_PER_HOUR` per client IP per hour.

### `POST /v1/mailboxes`
```json
{
  "platform": "apns" | "apns-sandbox" | "fcm",
  "token": "<APNs device token (hex) or FCM registration token>",
  "app": "chat.boson.app",
  "vapid": "<the install's VAPID public key, Ergo ISUPPORT VAPID=>",
  "install": "boson.ircforever.org",
  "challenge": "<from GET /v1/challenge>",
  "attestation": "<App Attest assertion | Play Integrity token | dev allowlist entry>",
  "key_id": "<iOS: App Attest key id, base64>",
  "attestation_object": "<iOS: App Attest attestation object, base64; first use of the key>"
}
```
`201`, `Location: <endpoint>`:
```json
{"id": "n5iInvov-zy_leIG6_rQGQ", "endpoint": "https://push.boson.chat/v1/push/n5iInvov-zy_leIG6_rQGQ", "secret": "<43 chars>"}
```
- `id` is 128 random bits (base64url); `secret` is 256 random bits, stored only as SHA-256.
  Keep the secret on the device; hand only the endpoint to the install.
- One mailbox per (platform, token, install): creating it again replaces the old one (new
  id and secret; the old endpoint then answers `404`, so Ergo drops it).
- `app` must be `PUSHRELAY_APNS_TOPIC` (iOS) / `PUSHRELAY_PLAY_INTEGRITY_PACKAGE` (Android).
- `install` is lowercased; it must be a DNS name.
- Errors: `400` (`invalid_request`, `app_mismatch`, `attestation_missing`), `401`
  (`challenge_invalid`, `attestation_failed`, `attest_key_unknown`), `403` (`install_blocked`),
  `429` (`rate_limited`: per-IP creation limit; `install_mailbox_limit`), `503`
  (`platform_unavailable`: no APNs/FCM credentials; `attestation_unavailable`,
  `attestation_upstream`).

#### Attestation
Every attested request binds the mailbox to the challenge through **client data**, the
UTF-8 string (values exactly as sent in the body, `\n` separated):
```
boson-push-v1\n<challenge>\n<platform>\n<token>\n<vapid>\n<install>
```
`clientDataHash = SHA-256(clientData)`.

- **iOS, App Attest.** First use of a key (`DCAppAttestService.generateKey`): send `key_id`
  and `attestation_object` = `attestKey(keyId, clientDataHash)`. The relay checks the
  certificate chain up to Apple's App Attestation Root CA, the nonce
  (`SHA-256(authData ‖ clientDataHash)` in extension `1.2.840.113635.100.8.2`), that the key
  id is the SHA-256 of the credential key, the rpId hash (`SHA-256(<team id>.<bundle id>)`),
  counter 0 and the aaguid, then stores the public key. Afterwards send `key_id` and
  `attestation` = `generateAssertion(keyId, clientDataHash)` (base64); the relay verifies the
  signature over `SHA-256(authenticatorData ‖ clientDataHash)` and that the counter went up.
  Both may be sent in the first request. If the relay answers `attest_key_unknown`
  (e.g. its database was reset), attest the key again.
  Development (`appattestdevelop`) keys count only with
  `PUSHRELAY_APP_ATTEST_ENV=development`, and only for `apns-sandbox`.
- **Android, Play Integrity.** Request a token with `requestHash` (standard request) or `nonce`
  (classic request) = `base64url(clientDataHash)` without padding, and send it as
  `attestation`. The relay decodes it server-side (`decodeIntegrityToken`, service account)
  and requires: our package name, the request hash, a verdict at most 10 minutes old,
  `PLAY_RECOGNIZED`, a signing certificate from `PUSHRELAY_PLAY_INTEGRITY_CERT_SHA256` (when
  set) and `MEETS_DEVICE_INTEGRITY` (or `MEETS_STRONG_INTEGRITY`).
- **Development builds.** A request on `apns-sandbox` (`PUSHRELAY_DEV_ALLOWLIST_PLATFORMS`)
  is let in without attestation and without a challenge if its `attestation` value or its
  device `token` is listed in `PUSHRELAY_DEV_ALLOWLIST_FILE` (one entry per line, `#`
  comments; read at start).

### `PATCH /v1/mailboxes/{id}`
`Authorization: Bearer <secret>`. Body `{"token": "<new device token>"}` when the OS rotated
it, or empty to just renew the mailbox (resets the 60-day unused clock; send it on app
start). `204`; `401 secret_required`, `403 secret_invalid`, `404 mailbox_not_found`.

### `DELETE /v1/mailboxes/{id}`
`Authorization: Bearer <secret>`. On sign-out, removing the server, or turning push off.
`204`, same errors as `PATCH`.

### `POST /v1/push/{id}` (RFC 8030)
What Ergo (or any Web Push sender) sends:
- `Authorization: vapid t=<JWT>, k=<key>` (RFC 8292; the older `WebPush <JWT>` +
  `Crypto-Key: p256ecdsa=` form also works). `k` must equal the mailbox's bound VAPID key,
  the JWT must be ES256-signed by it, `aud` must be the relay origin
  (`PUSHRELAY_PUBLIC_URL`'s scheme://host) and `exp` in the future and at most 24 h ahead.
- `Content-Encoding: aes128gcm`, body at most 4096 bytes (`PUSHRELAY_MAX_PAYLOAD_BYTES`).
- `TTL` (seconds; default 24 h when missing, capped at 28 days), `Urgency`
  (`very-low`/`low` → APNs priority 5 / FCM `NORMAL`; `normal`/`high` → 10 / `HIGH`),
  `Topic` (≤ 32 base64url characters; pushes with the same topic replace each other on the
  device: collapse id = `<mailbox id>.<16 hex of SHA-256(topic)>`).

`201 Created` with `Location` and the applied `TTL`. Otherwise:

| Status | `error` | When |
|---|---|---|
| 400 | `empty_body`, `invalid_ttl`, `invalid_urgency`, `invalid_topic` | bad request |
| 401 | `vapid_invalid` | missing/malformed VAPID, wrong key, bad signature, wrong `aud`, expired, `exp` > 24 h |
| 403 | `install_blocked` | the mailbox is paused (its install is blocked, or by the operator) |
| 404 | `mailbox_not_found` | unknown or deleted mailbox |
| 410 | `gone` | APNs/FCM said the device token is dead; the mailbox was deleted |
| 413 | `payload_too_large` | body over the limit, or too big for APNs/FCM once wrapped |
| 415 | `unsupported_encoding` | not `aes128gcm` |
| 429 | `rate_limited`, `daily_limit`, `install_rate_limited`, `upstream_rate_limited` | limits below, or APNs/FCM throttling |
| 502 | `upstream_error` | APNs/FCM failed |
| 503 | `platform_unavailable` | no credentials for the mailbox's platform |

Order of checks: mailbox → paused → VAPID → size/encoding/headers → per-mailbox bucket →
per-install hour → per-mailbox day → forward. Forwarding is synchronous, so a dead token is
reported to the sender on the same request.

### What the app receives
The body is the RFC 8291 ciphertext, untouched, standard base64.

**APNs** (`apns-push-type: alert`, `mutable-content: 1`, token auth with the `.p8` key, HTTP/2):
```json
{"aps": {"alert": {"body": "New message"}, "mutable-content": 1, "sound": "default"},
 "boson": {"v": 1, "mailbox": "<mailbox id>", "payload": "<base64 ciphertext>"}}
```
The Notification Service Extension finds the (device, server) key by mailbox id, decrypts
`payload` and rewrites the notification. `"New message"` is `PUSHRELAY_APNS_FALLBACK_BODY`.

**FCM** (HTTP v1, data-only, `android.priority` `HIGH`/`NORMAL`, `android.ttl`):
```json
{"message": {"token": "...", "data": {"v": "1", "mailbox": "<mailbox id>", "payload": "<base64 ciphertext>"},
             "android": {"priority": "HIGH", "ttl": "604800s", "collapse_key": "<if Topic>"}}}
```

Ergo bodies are 2048 bytes (its record size), 2732 in base64, well inside both services'
4 KB limits.

## Limits (§2.4)
| Env | Default | |
|---|---|---|
| `PUSHRELAY_MAILBOX_BURST`, `PUSHRELAY_MAILBOX_INTERVAL` | `10`, `6s` | per mailbox token bucket (`429 rate_limited`, `Retry-After` = interval) |
| `PUSHRELAY_MAILBOX_PER_DAY` | `300` | per mailbox per UTC day, in the database (`429 daily_limit`) |
| `PUSHRELAY_INSTALL_PER_HOUR` | `10000` | per install domain per clock hour (`429 install_rate_limited`); the first push above it raises an operator alert |
| `PUSHRELAY_CREATE_PER_IP_PER_HOUR` | `20` | mailbox creations per client IP (`TRUSTED_PROXIES` for `X-Forwarded-For`) |
| `PUSHRELAY_MAILBOXES_PER_INSTALL` | `0` (off) | mailboxes per install domain |
| `PUSHRELAY_MAILBOX_IDLE_DAYS` | `60` | mailboxes with no push or `PATCH` for this long are deleted (hourly) |

The bucket and hourly counters are in memory (one relay replica; they restart with the
process). Alerts go to the log (`warn`, `"alert":"install_hourly_ceiling"`), the
`pushrelay_install_limit_alerts_total` metric, and `PUSHRELAY_ALERT_WEBHOOK_URL` (JSON POST)
when set.

## Operator API (internal listener, `INTERNAL_ADDR`, default `:3001`)
Never routed publicly. `/metrics`, `/healthz`, `/readyz` are open; `/admin/v1` needs
`X-Internal-Token: $PUSHRELAY_INTERNAL_TOKEN` (or `Authorization: Bearer`) and answers `503`
when the token is not set.

| Method | Path | |
|---|---|---|
| GET | `/admin/v1/installs` | per install: mailboxes (by platform, paused), pushes this hour / today, hourly ceiling, blocked |
| GET | `/admin/v1/installs/{install}` | one install |
| GET | `/admin/v1/blocks` | blocked installs |
| PUT | `/admin/v1/blocks/{install}` | block (`{"reason": "..."}`): pushes `403`, mailboxes paused, no new mailboxes |
| DELETE | `/admin/v1/blocks/{install}` | unblock, resume its mailboxes |
| GET | `/admin/v1/mailboxes/{id}` | one mailbox (token shortened) |
| DELETE | `/admin/v1/mailboxes/{id}` | delete a mailbox |
| POST | `/admin/v1/mailboxes/{id}/pause`, `/resume` | pause / resume one mailbox |
| POST | `/admin/v1/expire` | run the unused-mailbox expiry now |

The same as a CLI (talks to the running relay):
```sh
docker compose exec pushrelay /app/pushrelay admin installs
docker compose exec pushrelay /app/pushrelay admin block spam.example --reason "abuse"
docker compose exec pushrelay /app/pushrelay admin unblock spam.example
docker compose exec pushrelay /app/pushrelay admin delete-mailbox <id>
```

### Metrics
`pushrelay_pushes_total{outcome}` (accepted, not_found, unauthorized, blocked, too_large,
rate_limited_mailbox/_install/_daily, gone, upstream_error, ...),
`pushrelay_push_body_bytes`, `pushrelay_upstream_requests_total{service,result}`,
`pushrelay_upstream_request_seconds{service}`, `pushrelay_mailboxes{platform}`,
`pushrelay_mailbox_operations_total{op,outcome}`, `pushrelay_attestations_total{method,result}`,
`pushrelay_install_limit_alerts_total`, `pushrelay_mailboxes_expired_total`, plus Go/process.

### Logs
JSON on stdout. Pushes log mailbox id, install, platform, size and outcome only: never
bodies, secrets, VAPID JWTs or device tokens (the admin API shows the first 8 characters).

## Configuration
Env vars (names agreed with the stack's `pushrelay` profile):

| Env | Default | |
|---|---|---|
| `PUSHRELAY_PUBLIC_URL` | `http://localhost:8080` | relay base URL: mailbox endpoints and the VAPID `aud` (`https` required in production) |
| `DATABASE_URL` | – | Postgres URL; `memory` for development (refused in production) |
| `PUSHRELAY_AUTO_MIGRATE` | `true` | run migrations on `serve` |
| `HTTP_ADDR`, `INTERNAL_ADDR` | `:8080`, `:3001` | listeners |
| `TRUSTED_PROXIES` | – | CIDRs/IPs whose `X-Forwarded-For` is honoured |
| `PUSHRELAY_INTERNAL_TOKEN` | – | operator API token |
| `LOG_LEVEL` | `info` | |
| `PUSHRELAY_ENV` | `production` in the image | `development` allows http and the memory store |
| `PUSHRELAY_APNS_KEY_FILE` | – | `.p8` key; a missing file just disables APNs |
| `PUSHRELAY_APNS_KEY_ID`, `PUSHRELAY_APNS_TEAM_ID` | – | key id, Apple team id |
| `PUSHRELAY_APNS_TOPIC` | `chat.boson.app` | bundle id (`apns-topic`, iOS `app`) |
| `PUSHRELAY_APNS_FALLBACK_BODY` | `New message` | alert shown if the extension can't run |
| `PUSHRELAY_FCM_CREDENTIALS_FILE` | – | Firebase service account JSON; a missing file disables FCM |
| `PUSHRELAY_FCM_PROJECT_ID` | from the file | |
| `PUSHRELAY_APP_ATTEST_APP_ID` | `TEAM_ID.TOPIC` | App Attest app id; empty (no team id) = App Attest off |
| `PUSHRELAY_APP_ATTEST_ENV` | `production` | `development` also accepts dev-signed keys (apns-sandbox only) |
| `PUSHRELAY_PLAY_INTEGRITY_PACKAGE` | `chat.boson.app` | Android package (`app` for fcm) |
| `PUSHRELAY_PLAY_INTEGRITY_CERT_SHA256` | – | allowed signing cert digests, comma-separated (hex, `AA:BB:..` or base64url) |
| `PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE` | the FCM one | service account for `decodeIntegrityToken` |
| `PUSHRELAY_DEV_ALLOWLIST_FILE` | – | development allowlist (see Attestation) |
| `PUSHRELAY_DEV_ALLOWLIST_PLATFORMS` | `apns-sandbox` | where the allowlist applies |
| `PUSHRELAY_MAILBOX_*`, `PUSHRELAY_INSTALL_PER_HOUR`, `PUSHRELAY_CREATE_PER_IP_PER_HOUR`, `PUSHRELAY_MAILBOXES_PER_INSTALL` | see Limits | |
| `PUSHRELAY_MAX_PAYLOAD_BYTES` | `4096` | |
| `PUSHRELAY_DEFAULT_TTL`, `PUSHRELAY_MAX_TTL` | `24h`, `672h` | |
| `PUSHRELAY_UPSTREAM_TIMEOUT` | `10s` | APNs/FCM request timeout |
| `PUSHRELAY_ALERT_WEBHOOK_URL` | – | JSON POST on operator alerts |
| `PUSHRELAY_CHALLENGE_TTL` | `5m` | |

Test-only overrides: `PUSHRELAY_APNS_ENDPOINT`, `PUSHRELAY_APNS_SANDBOX_ENDPOINT`,
`PUSHRELAY_FCM_ENDPOINT`, `PUSHRELAY_PLAY_INTEGRITY_ENDPOINT`,
`PUSHRELAY_APP_ATTEST_ROOT_CA_FILE`.

## What the operator provides
- **APNs:** an APNs Auth Key (`.p8`) with its Key ID, the Apple Team ID, and the bundle id
  (`chat.boson.app`). One key serves production and sandbox.
- **Firebase:** a Firebase project with the Android app, and a service account key (JSON) with
  the *Firebase Cloud Messaging API Admin* role.
- **Play Integrity:** link the Google Cloud project in Play Console → App integrity, enable the
  Play Integrity API, and give the service account (the FCM one or
  `PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE`) access to decode tokens; set
  `PUSHRELAY_PLAY_INTEGRITY_CERT_SHA256` to the app signing key's SHA-256 (Play Console).
- **App Attest:** enable the App Attest capability for the app id; nothing to configure on the
  relay beyond the team id / app id.

## Storage
Postgres (`db/migrations`): `mailboxes`, plus `blocked_installs`, `challenges` (single-use,
hashed) and `app_attest_keys` (public key + counter). Per mailbox: platform, device token,
VAPID key, install domain, secret hash, timestamps and the day's push count; no account
names, nicks or message data.

## Development
```sh
cp .env.example .env   # in-memory store, dev admin token
make run               # :8080 public, :3001 internal
make test              # unit + end-to-end tests (race detector)
make test-pg-up test-integration test-pg-down   # plus the Postgres store
make lint              # vet, gofmt, golangci-lint
make docker
```
The end-to-end tests (`http/e2e_test.go`) run the whole relay against fake APNs (HTTP/2 over
TLS), FCM, Play Integrity and Google OAuth, send real pushes with
`github.com/ergochat/webpush-go/v2` exactly as Ergo does (RFC 8291 encryption, VAPID), and
decrypt what reaches the fake APNs/FCM with the device key.

Layout: `cmd/` (entry), `internal/commands` (CLI), `config/`, `db/` (migrations),
`internal/db` (Postgres + in-memory stores), `internal/services/{attest,delivery,mailboxes,push,ratelimit,alert}`,
`internal/webpush` (VAPID), `http/` (wiring, handlers, middleware), `metrics/`.

Releases: conventional commits on `main` → semantic-release tags `vX.Y.Z` and pushes
`harbor.floret.dev/boson/pushrelay:<version>` and `:latest` (amd64 + arm64).

## License
AGPL-3.0, see [LICENSE](LICENSE).
