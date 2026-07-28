# StackStorm Boundary

The files in this directory are inert, disabled, notification-only desired-state contracts.
`webhook-policy.yaml` defines the ingress requirements, `event.schema.yaml` closes
the actual four-field event shape, and `allowlist.yaml` is the
only permitted workflow set. They are not runnable StackStorm configuration and are
not proof of a live StackStorm deployment.

Repository tests validate these documents as closed contracts: unknown fields,
workflow or action names, command/credential-like additions, incomplete payload
requirements, and weakened TLS, signature, replay, rate, audit, timeout, cooldown,
or enablement controls fail static validation. This is test-time desired-state
validation only. Framing, signature, and replay exercises are contract/vector
tests only; no StackStorm policy or runtime enforcement was installed or tested.
`scripts/sentinel.py` independently pins the replay store's shared-linearizable,
atomic reserve-if-absent, fail-closed, restart-persistent semantics and the
duplicate-member-rejecting parser/order. Coordinated policy-and-schema weakening
therefore fails static validation. This independent pin is still not a replay
store, JSON webhook parser, or runtime handler.

Zabbix must send events through an authenticated TLS reverse proxy using the
configured HMAC secret reference. The proxy must reject missing, stale, replayed,
or invalid signatures before forwarding a minimal event. StackStorm must accept
only the named workflow and a schema-validated payload containing an asset ID,
event ID, severity, and opaque references. Credentials and tokens never belong
in event payloads or action parameters.

### `sentinel-hmac-v1` (inert contract)

An implementation must first reject a request unless all of these rules hold:

- The method is the case-sensitive token `POST`. The request target is the raw
  ASCII HTTP origin-form target. Its path portion is exactly
  `/api/v1/webhooks/zabbix`; it has either no query or `?` followed by a non-empty
  query. The query bytes, delimiter order, and repeated parameters are preserved
  without parsing, sorting, decoding, or re-encoding. A percent sign, fragment,
  non-ASCII/control/space byte, backslash, or path `.`/`..` segment is rejected.
- HTTP field names are matched case-insensitively. Every request field name must
  occur exactly once case-insensitively, not merely the signed fields. Combined
  duplicate values and obsolete folded values are rejected. Field values are
  not trimmed: leading or trailing SP/HTAB and any CR/LF are rejected.
- Exactly one each of `X-Sentinel-Timestamp`, `X-Sentinel-Source`,
  `X-Sentinel-Signature`, `Content-Type`, and `Content-Encoding` is present.
  Content-Type is exactly `application/json; charset=utf-8` and
  Content-Encoding exactly `identity`, including casing and spacing. The source
  value is exactly the allowlisted ASCII identity
  `zabbix-notification-webhook`; signing it binds the asserted identity.
- `Transfer-Encoding` is rejected whenever present. Exactly one
  `Content-Length` field is required; its value is canonical unsigned decimal
  with no leading zero (except `0`) and must equal the number of raw body
  octets. An empty body therefore requires exactly `Content-Length: 0`.
  Conflicting framing or content encodings are rejected rather than normalized.
  An HTTP/2 terminating proxy must produce the identical raw origin-form
  request target and body octets that an HTTP/1.1 request would supply before
  signature verification; reconstructed, decoded, or re-encoded values fail.
- The body input to SHA-256 is the exact HTTP message-body byte sequence before
  any content decoding or Unicode/JSON normalization. Its digest is
  lowercase 64-character hexadecimal. Thus UTF-8 body bytes are allowed even
  though every canonical component is ASCII.
- The timestamp is ASCII `0` or a non-zero decimal integer of at most ten digits,
  with no sign or leading zero. Parse it as integer Unix seconds. Compare it to
  the verifier's integer Unix-seconds clock. With the declared 300-second window,
  timestamps from `now - 300` through `now + 300` are accepted inclusively;
  lower values are stale and higher values are future-skew failures.

After those checks, ASCII-encode these seven components in exact order: timestamp
header value, uppercase method, exact raw origin-form request target (including
the unchanged query when present), Content-Type value, Content-Encoding value,
lowercase body SHA-256 hex, and source header value. Join adjacent components
with exactly one LF byte (`0x0a`) and append no trailing LF. HMAC-SHA-256 those
canonical bytes and compare the supplied signature as exactly 64 lowercase hex
characters using a constant-time comparison. The signature header itself is not
a canonical component.

The replay identity is exactly source identity plus event ID. Timestamp and MAC
are not part of that identity, so re-signing the same event does not make it new.
After signature verification, reject duplicate JSON member names at every object
depth before schema validation or event-ID extraction. A generic JSON parser that
silently keeps the first or last duplicate is not conforming.

After JSON and schema validation, reserve the event identity with one atomic
insert-if-absent operation in a shared linearizable store before forwarding. A
store error rejects the event; a local worker cache or check-then-insert sequence
is prohibited. The reservation must survive every worker restart for its full
retention. At first successful reservation, record the verifier's integer
Unix-seconds clock as `first_receipt`. Pin that identity independently of later
signatures, retain it, and reject every presentation of it through the inclusive instant
`max(first_receipt + window + accepted_future_skew, signed_timestamp + window)`.
Here both window and accepted future skew are 300 seconds, so the first term is
`first_receipt + 600`; this prevents the accepted future-skew range from outliving
the event-level replay record. These are contract semantics only. `payload.max_bytes`
and `payload.forbidden` are contract
declarations, not enforcement: no handler exists in this repository to enforce
them (or any rule above). Runtime receipt/enforcement remains blocked until a
separately reviewed handler and protected runtime test exist.

The allowlist is notification-only and `enabled: false` until a human approves
the boundary. No action may restart, change, or log in to a target. OpenBao
references are resolved only by an approved handler at execution time. Any
future remediation requires a separate reviewed workflow, target allowlist,
timeouts, retry and cooldown limits, concurrency locking, post-action checks,
audit records, rollback/escalation, and an explicit enablement decision.

Compose intentionally has no StackStorm service or automation profile. The invalid
monolithic image was removed and was not replaced by a partial component stack.
Every notification route also has explicit `enabled: false`. Policies may continue
to reference those route IDs as desired intent, but this commissioning baseline
cannot deliver through them.
Runtime receipt, authentication, policy installation, rule registration/evaluation,
audit, notification delivery, and restore testing remain blocked and unverified.
Receipt remains blocked until a complete deployment design is reviewed and a
separately approved runtime test provides evidence without executing remediation.

The `sentinel rollback` command is likewise review-only: it verifies and reports
a recorded plan but performs no reverse operation or infrastructure mutation.
