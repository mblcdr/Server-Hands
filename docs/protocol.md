# Protocol v1 (draft)

Single version, no negotiation, no fallback. Anything else is rejected.

## Keys

| Key | Algorithm | Where | Purpose |
|---|---|---|---|
| Server identity `S` | Ed25519 | `/var/lib/server-hands/identity.key` (0600, root) | signs every server message; pinned by clients |
| Server TLS key | ECDSA P-256 self-signed cert | state dir | transport only; SPKI SHA-256 pinned by clients |
| Request ephemeral `E` | X25519 | RAM only, one per request | HPKE recipient key; destroyed after approval |
| Device identity `D` | ECDSA P-256 | Android Keystore (StrongBox preferred), non-exportable, `setUnlockedDeviceRequired` | signs approvals; public key stored on server at pairing |
| Vault key | AES-256-GCM | Android Keystore, per-use biometric | encrypts the passphrase vault blob |

Primitives: HPKE RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. Hash: SHA-256. Randomness: OS CSPRNG.

## Encoding

Messages are JSON. Signed messages use an envelope `{ "body": "<base64url of exact body bytes>", "sig": "<base64url>" }`. Signatures cover `domain_label || 0x00 || body_bytes`. Verifiers parse the body only after the signature verifies. No canonicalization is needed because the signed bytes are transmitted verbatim.

Domain labels: `hands/v1/server-reply`, `hands/v1/device-request`, `hands/v1/approve`, `hands/v1/pair`.

## Pairing

1. Operator runs `sudo handsctl pair` over SSH. Server creates a 32-byte one-time token (expires in 5 minutes, usable once, rate-limited) and prints a QR for
   `hands://pair?v=1&host=<ip-or-name>&port=<p>&spki=<b64url sha256>&sid=<b64url Ed25519 pub>&tok=<b64url 32B>`.
2. App scans the QR (in-app scanner only; the `hands://` scheme is **not** registered as a deep link). It connects with TLS pinned to `spki`.
3. App generates `D` and sends `POST /v1/pair` `{ tok, device_pub, device_name }`.
4. Both sides compute `SAS = decimal6(SHA-256("hands/v1/sas" || sid || device_pub || tok))`. The server console and the phone display it; the operator confirms they match in `handsctl pair` (which blocks on confirmation).
5. On confirmation the server stores `device_id = SHA-256(device_pub)[0..16]`, `device_pub`, `name`, `created_at`, replies with a signed ack. The token is burned.
6. App stores `{server_id (hash of S), S, spki, host, name}` and then, after `BiometricPrompt` + Keystore key creation, the vault entries for each drive (LUKS UUID + passphrase).

## Request lifecycle

The server creates a request per boot (all locked, non-crypttab containers): `req_id` (16 random bytes), `created_at`, `expires_at` (+10 min), list of `{luks_uuid, label, size}`, `E_pub`.

### `POST /v1/requests/list`

Client body (signed by `D`, label `hands/v1/device-request`): `{ device_id, client_nonce (32B), ts }`.

The body is parsed once, only to read `device_id` and pick the verification key; its values are used only after the signature verifies. Server verifies device is paired, `|now - ts| < 120 s`, and returns an envelope signed by `S` (label `hands/v1/server-reply`):
`{ client_nonce, server_time, requests: [ { req_id, expires_at, drives: [...], e_pub, status } ] }`.

The app verifies the signature against pinned `S`, checks `client_nonce` matches, checks `server_time` is close to its clock, and only then trusts anything in the reply.

### `POST /v1/requests/{req_id}/approve`

The app:
1. Re-verifies the latest list reply for this `req_id` (fresh nonce, not older than 60 s).
2. Shows server name, key fingerprint and drive labels, then the BiometricPrompt (CryptoObject) decrypts the vault blob.
3. Builds the binary plaintext (see "Normative encodings") for the selected drives only.
4. `info` and `aad` as defined in "Normative encodings".
5. `(enc, ct) = HPKE.Seal(E_pub, info, aad, plaintext)`; zeroes plaintext and passphrases.
6. Signs the approve message (see below) with `D` and POSTs `{ device_id, client_nonce, uuids, enc, ct, sig }`. `uuids` are the hyphenated LUKS UUIDs in strictly ascending order; the server turns them into the AAD, so any mismatch with what was sealed fails the HPKE open.

The server:
1. Looks up the request (must be `pending`, unexpired), device (paired), checks `client_nonce` was one it issued within the last 120 s and not yet used.
2. Verifies the device signature, then `HPKE.Open` with `E_priv`; **immediately marks the request consumed and zeroizes `E_priv`** whether or not the unlock succeeds.
3. Hands each `(uuid, passphrase)` to the unlock child over a pipe (never argv/env/file), zeroizes on completion.
4. Replies (signed by `S`) per drive `{ luks_uuid, result: ok | bad_passphrase | already_open | error_code }`. No passphrase or key material is ever echoed.
5. For `bad_passphrase`, creates a **new** request (fresh `req_id`, fresh `E`) so the app retries. After 5 failures per device in 10 minutes, back off 5 minutes.

## Wire bodies (Phase 2, implemented in `hands-proto::wire`)

All JSON, unknown fields rejected, binary fields base64url (no padding), `device_id` and `req_id` are the raw 16 bytes in base64url.

- `POST /v1/pair` `{tok, device_pub (SPKI DER), device_name}`. The request **blocks** (up to 5 min) while the operator compares the SAS in `handsctl pair`; the reply is a server-signed (`hands/v1/pair`) `{device_id, server_time}`. The token is burned the moment a correct one is presented; 5 wrong tokens burn it too.
- `POST /v1/requests/list`: device-signed `Envelope` in, server-signed `Envelope` of `{client_nonce, server_time, requests:[{req_id, expires_at, drives, e_pub, status}]}` out.
- `POST /v1/requests/{req_id}/approve`: see above; reply is server-signed `{client_nonce, req_id, results:[{luks_uuid, result}]}`.
- `POST /v1/scripts/list`: device-signed `Envelope` of the same `{device_id, client_nonce, ts}` body as `requests/list` (same domain; the nonce is single-use, so a captured envelope cannot be replayed at either endpoint). Reply: server-signed `{client_nonce, server_time, unlocked, scripts:[{name, label, mode: auto|manual, state: idle|queued|running|ok|failed, finished_at}]}`.
- `POST /v1/scripts/run`: device-signed `Envelope` of `{device_id, client_nonce, ts, script}` (unknown fields are rejected, so it cannot be confused with a list body). `script` is a name from the server's config; the phone never sends a path or arguments. Refused with `not_unlocked` until every drive is unlocked, `busy` if already queued or running, `unknown_script`. Reply: server-signed `{client_nonce, script, state}`; the script runs in the background and the outcome is read with `scripts/list`.
- Error HTTP status: 400 `bad_request`, 401 `unauthorized`, 404 `unknown_script`, 409 `replayed` / `busy` / `not_unlocked`, 410 `expired`, 429 `rate_limited`, 500 `internal`.
- TLS 1.3 only, self-signed P-256 certificate (CN `server-hands`; Java/Android reject an empty subject DN); clients pin the SHA-256 of its SubjectPublicKeyInfo.

## Errors

Constant-shape error bodies: `{ "error": "<code>" }`, codes: `unauthorized`, `expired`, `replayed`, `bad_request`, `rate_limited`, `unknown_script`, `busy`, `not_unlocked`, `internal`. No detail that distinguishes "unknown device" from "bad signature".

## Rules the implementations must enforce

- Passphrases only ever exist as raw bytes in `Zeroizing`/`ByteArray` containers; no string conversion, no logging, no panics with payload in the message, no `Debug` on secret types.
- Reject unknown JSON fields in signed bodies; reject duplicate `uuid` entries.
- Constant-time comparison for tokens, hashes and nonces.
- Server key change on the client = hard failure; only a fresh QR pairing recovers.
- The unlock child receives secrets over a pipe, runs with `mlockall`, `PR_SET_DUMPABLE=0`, and a cgroup memory cap sized for argon2id (1.5 GiB headroom).

## Test vectors

`protocol/vectors/*.json`: fixed keys and nonces with expected envelopes, HPKE `enc`/`ct`, and signature bytes. Rust and Kotlin both run them. Negative vectors: replayed nonce, wrong server key, wrong `info` fields, truncated `ct`, expired request, unknown device, swapped `req_id`.

## Normative encodings (implemented in `hands-proto`, covered by `protocol/vectors/v1.json`)

- `lp(f1, f2, ...)` = concatenation of `u32be(len(fi)) || fi`.
- `b64` = base64url without padding. Vectors use hex for raw bytes.
- Signed bytes: `domain_label || 0x00 || body`.
- Server signature: Ed25519 (RFC 8032), raw 64 bytes, verified strictly (no malleable encodings). Server public key: raw 32 bytes.
- Device signature: ECDSA P-256 with SHA-256, **DER**-encoded (what Android `Signature("SHA256withECDSA")` emits). Device public key: X.509 SubjectPublicKeyInfo DER (`PublicKey.getEncoded()`). `device_id = SHA-256(spki)[0..16]`.
- HPKE: RFC 9180 base mode, KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0003 ChaCha20-Poly1305. `enc` = 32 bytes; `ct` = ciphertext || 16-byte tag. Single-shot seal/open, empty exporter context.
- `info = lp("hands/v1/hpke", SHA-256(S_pub), req_id, client_nonce, device_id)`.
- `aad = lp(uuid_1, ..., uuid_n)` with raw 16-byte LUKS UUIDs in **strictly ascending** order (no duplicates).
- Approve message (what `D` signs) = `signed_bytes("hands/v1/approve", lp(req_id, client_nonce, enc, SHA-256(ct), aad))`.
- Plaintext: `0x01 || count(u8) || count x (uuid[16] || len(u16be) || passphrase bytes) || zero padding` to a multiple of 256 bytes. Count 1..=32, passphrase length 1..=1024, UUIDs strictly ascending, padding must be all zero, anything else is rejected. Binary (not JSON) so a passphrase never has to pass through a string type.
- SAS = `u32be(SHA-256("hands/v1/sas" || lp(S_pub, device_spki, token))[0..4]) mod 10^6`, zero-padded to 6 digits.
- All verification failures collapse to one opaque error; no decoder reports *why* it failed.
