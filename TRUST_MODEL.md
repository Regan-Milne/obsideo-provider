# Obsideo Security & Trust Model

How Obsideo protects customer data, verifies provider integrity, and what the
network does and does not currently guarantee.

> This document describes architecture. For reporting a vulnerability, see
> [SECURITY.md](SECURITY.md).

**Last updated: 2026-09-05.** If a dated claim here disagrees with the live
service surfaces (obsideo.io/terms, obsideo.io/llms.txt, agents.md), the more
recently dated source wins and this file needs a refresh.

---

## The architectural principle

**End-to-end encryption is not a feature of Obsideo; it is a definitional
property.** The system is architecturally incapable of accessing customer
plaintext. Not by policy. Not by operational discipline. By architecture. No
amount of operator access to coordinator infrastructure allows decryption of
customer data.

Every other decision in this document flows from that principle.

**Status:** shipped and current. The KMS-pattern used by earlier iterations —
which routed per-object data keys through the coordinator via `/v1/kms/wrap`
and `/v1/kms/unwrap` — has been removed entirely. Those endpoints do not exist
in the coordinator. There is no escrow, no recovery service, and no
operator-side decryption path.

---

## Encryption

Encryption happens on the client, before any byte leaves the client's machine,
in one of two modes. The coordinator has no path to plaintext in either.

| Mode | Who encrypts | Customer signing key |
|---|---|---|
| `managed` (default) | The Obsideo SDK, using a customer-held keypair | Optional |
| `external` | The customer's own E2EE layer, before the SDK sees the data | **Required** |

Mode is set per account via `encryption_mode` at account creation. External
mode shipped 2026-05 and requires `customer_signing_public_key`.

### Managed-mode encryption flow

```
Upload:
  1. SDK generates a random 32-byte AES-256 data key K
  2. SDK encrypts plaintext with AES-256-GCM(K) -> nonce(12) || ciphertext || tag(16)
  3. SDK locally wraps K with the customer's public key (HPKE)
  4. SDK uploads ciphertext to providers
  5. SDK stores wrapped_K as object metadata on the coordinator (opaque to it)

Download:
  1. SDK fetches wrapped_K from the coordinator (opaque blob)
  2. SDK downloads ciphertext from a provider
  3. SDK locally unwraps wrapped_K with the customer's private key
  4. SDK decrypts ciphertext locally with K
  5. K is discarded after use
```

The plaintext data key **never touches the coordinator** at any point in any
flow. Wrap and unwrap happen locally, on the client, with the customer's own
keypair.

### Keys and their custody

| Key | Held by | Obsideo has access? |
|---|---|---|
| Per-object AES-256-GCM data key (K) | Client memory only, briefly | **No** |
| Customer master keypair (wraps K) | Customer only | **No** |
| Customer signing key (Ed25519) | Customer only | **No** |
| Wrapped K (ciphertext blob) | Coordinator metadata | Yes, cannot decrypt |
| Ciphertext file bytes | Providers | Yes, cannot decrypt |

---

## What the coordinator can and cannot do

### Can

- Maintain account identity and issue API keys
- Store object metadata (bucket, key, merkle root, chunk hashes, wrapped_K)
- Maintain the provider directory and select providers for uploads
- Issue upload/download/challenge tokens signed with Ed25519
- Run challenge cycles to verify provider integrity
- Evict underperforming providers and trigger re-replication
- Track usage and calculate payment accruals
- Publish signed snapshots of the provider directory for customer continuity

### Cannot

- **Decrypt customer data.** It holds wrapped key blobs but not the customer's
  private key. Unwrapping is impossible.
- **Recover data if the customer loses their key.** This is the tradeoff of
  genuine end-to-end encryption.
- **Reveal plaintext under subpoena or legal process.** The capability does
  not exist to be compelled.
- **Administratively delete a live customer object.** The coordinator's admin
  object-delete route was removed and deployed to production 2026-07-23. It
  no longer exists.
- Access plaintext file contents or plaintext data keys at any point.
- Execute code on provider machines.

---

## What providers can and cannot see

### Can see

- Ciphertext bytes (opaque)
- Merkle root and chunk hashes (cryptographic identifiers, not content)
- File size
- Which coordinator issued the tokens
- Challenge requests (random chunk index + nonce)

### Cannot see

- Plaintext file content
- Encryption keys in any form — data keys, customer master keys, wrapped blobs
- File names or user-defined metadata (held by the coordinator, not providers)
- Other providers' data or identities
- Account information beyond the `account_id` carried in tokens

---

## Proof-of-retrievability

The network continuously verifies that providers actually hold what they claim
to hold. This is independent of the encryption model.

### Challenge cycle

The coordinator runs a challenger on a configurable interval (default: every
4 hours). For each object on each provider:

1. Coordinator selects a random chunk index
2. Coordinator sends a challenge token to the provider: `POST /challenge`
3. Provider returns the merkle proof for that chunk within the timeout
4. Coordinator verifies the proof against the stored merkle root and replica
   commitment

Providers are paid on data they can prove they hold. Unverified holding is not
compensated.

### What this does and does not currently give you

**Today, challenge proofs are issued and recorded by the coordinator.** A
customer cannot yet independently verify a proof record without trusting the
coordinator's bookkeeping. Work to give each provider a signing identity — so
that challenge responses become provider-signed, attributable artifacts a
customer can retain and verify against a published provider public key — is in
flight. Publication of a transparency log is deliberately deferred until that
signing foundation is real.

The claim this design targets is **provider-signed and independently
verifiable**. It is not "trustless," and this document will not describe it as
trustless until the signing work has shipped to the fleet.

No headline pass-rate figure is published, because coordinator bookkeeping
divergence and actual data loss are not yet cleanly separated in the failure
statistics. A single canonical accounting classifier for every byte bucket
(contracted, lapsed, ghost, orphan) is in progress.

### Scoring

Each provider carries a score from 0.0 to 1.0:

- **Start:** 1.0
- **Challenge pass:** score recovers toward 1.0 (configurable rate)
- **Challenge fail:** score decays (configurable rate)
- **Score = 0:** provider is evicted from object assignments

Scores affect provider selection for new uploads and payment calculations.

### Object health states

| State | Meaning |
|-------|---------|
| `pending` | Uploaded but not yet audited |
| `verified` | Most recent challenge passed on all providers |
| `degraded` | A provider failed and was evicted; fewer replicas than target. The replicator will restore replication. |

### Replication

Default replication factor is 3, configurable per upload. When a provider is
evicted, the replicator copies the object to another healthy provider to
restore the target replica count. Placement healing prefers failure-domain
diversity when the fleet allows it.

---

## Token authentication

All data operations (upload, download, challenge, replication) require a token
signed by the coordinator's Ed25519 private key.

### Token format

JWTs containing:

- `merkle_root` — which object this token authorizes
- `provider_id` — which provider may use it
- `account_id` — which account owns the object
- `type` — upload, download, or challenge
- `iat` / `exp` — issued-at and expiration

### Verification flow

1. Coordinator signs the token with its Ed25519 private key
2. Provider receives the request with `Authorization: Bearer {token}`
3. Provider verifies the signature using the coordinator's public key, fetched
   from `GET /public-key` on startup
4. Provider checks token type, merkle root, provider ID, and expiration
5. The request proceeds only if all checks pass

Forged or expired tokens are rejected. Token signing authorizes **access to
stored ciphertext only**. Tokens neither carry nor enable key material;
possession of a token grants no decryption capability.

---

## Delete authority

The principle: a coordinator-issued instruction to delete or modify customer
data is not legitimate without a customer signature on it.

**Shipped:** the coordinator's administrative object-delete path has been
removed entirely (production, 2026-07-23). The platform cannot unilaterally
destroy a live customer object. Providers implement local verification of
customer-signed deletes — `POST /delete/{merkle}`, Ed25519-verified against
locally held ownership records, with no coordinator in the loop.

**In flight:** SDK emission of signed deletes, and fleet-wide deployment of the
verifying provider build. **Until both land, deletes are authorized by the
customer's account credentials rather than gated on a customer signature.**
The live terms and agents.md state this in the same terms.

Separately, providers garbage-collect aged non-contracted data on their own
hardware and on their own schedule, with a recheck pass and a quarantine hold
before anything is reclaimed. Live on the fleet since June 2026.

---

## Continuity and recovery

A customer who retains their private key, their per-object recovery manifests,
and a signed snapshot of the provider directory can pull ciphertext directly
from providers and decrypt locally.

**What ships today is a bounded evacuation path.** The SDK maintains a local
recovery bundle — recovery manifest, cached signed provider directory,
pre-fetched download authorizations — and the evacuation tool uses it to fetch
ciphertext from providers without the coordinator. It works for the validity
window of the most recently pre-fetched authorizations. It is a bounded
bridge, not an indefinite capability. obsideo.io/terms section 7 states this
limitation in plain language.

**In active development:** durable coordinator-independent recovery, where the
customer signs their own download authorizations and providers verify them
locally against ownership records written at upload time, with no expiring
coordinator-issued material anywhere in the path. The protocol and
provider-side implementation exist and have been validated end to end on a
local network with the coordinator stopped. Fleet deployment is the remaining
work.

Until that ships, this section is not a guarantee that data is recoverable at
an arbitrary future date with no Obsideo participation.

---

## Provider identity

Each provider generates an Ed25519 keypair on first startup:

- **Private key:** `{data_dir}/.identity_ed25519`, mode 0600
- **Public key:** sent to the coordinator at registration (hex-encoded, 32 bytes)
- **Purpose:** uniquely identifies the provider; enables idempotent
  re-registration (same pubkey + address = same provider, not a duplicate)

Losing the private key means losing the provider's identity; the operator must
re-register as a new provider. Provider identity is entirely separate from
customer key material.

---

## Network topology

```
Customers / agents
    |
    | HTTPS (API key auth; no key material transits)
    v
Coordinator  (coordinator.obsideo.io)
    |
    | HTTPS (coordinator-signed tokens; no key material transits)
    v
Providers (operator-owned hardware, direct public ingress)
```

- Customer to coordinator: HTTPS, API-key authenticated. Only metadata and
  wrapped key blobs cross this boundary.
- Coordinator to provider: HTTPS, signed tokens. Only ciphertext crosses.
- Provider to coordinator: HTTPS, registration and heartbeat.
- Provider to provider: HTTPS replication, authorized by coordinator-signed
  tokens, carrying only ciphertext.

Providers serve over **direct public ingress**. Relay tunnels (Tailscale
Funnel and similar) were deprecated for the data path in July 2026 — they were
relay-latency-bound and rate-limited, and were removed from the live fleet.

No component of Obsideo's infrastructure handles plaintext data or plaintext
data keys at any point.

---

## What is not true yet

Stated plainly, so this document cannot be read as promising more than the
network delivers:

- Challenge proofs are **not** independently verifiable by customers today.
  They are coordinator-issued and coordinator-recorded.
- There is **no** published transparency log.
- There is **no** published headline pass-rate figure.
- Deletes are **credential-authorized**, not signature-gated, until SDK
  emission and fleet deployment complete.
- Coordinator-independent recovery is **bounded** by the validity window of
  pre-fetched authorizations, not indefinite.

Each of these is tracked in the roadmap, and none of them are described as
shipped on any live service surface.
