# Obsideo Security & Trust Model

How Obsideo protects user data, verifies provider integrity, and maintains
a trustless storage network.

## Encryption

All data stored on provider nodes is encrypted by default.

### At-rest encryption

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key management:** Each file gets a unique 32-byte random data key
- **Key wrapping:** Data keys are wrapped by the coordinator's KMS before storage
- **Provider visibility:** Providers store and serve ciphertext. They never see the data key or the plaintext.

### Encryption flow

```
Upload:
  1. SDK generates random 32-byte key K
  2. SDK encrypts plaintext with AES-256-GCM(K) -> nonce(12) || ciphertext || tag(16)
  3. SDK sends K to coordinator: POST /v1/kms/wrap -> wrapped_key
  4. SDK uploads ciphertext to providers (providers never see K)
  5. SDK stores wrapped_key as object metadata on coordinator

Download:
  1. SDK fetches wrapped_key from coordinator
  2. SDK unwraps: POST /v1/kms/unwrap -> K
  3. SDK downloads ciphertext from provider
  4. SDK decrypts locally with K
  5. K is discarded after use
```

The coordinator holds the master wrapping key and can unwrap data keys for
authorized accounts. The coordinator does not store the plaintext data.

Providers hold the ciphertext but cannot decrypt it without the data key,
which they never receive.

## Proof-of-retrievability

The network continuously verifies that providers actually hold the data
they claim to hold.

### Challenge cycle

The coordinator runs a challenger process on a configurable interval
(default: every 4 hours). For each object on each provider:

1. Coordinator selects a random chunk index
2. Coordinator sends a challenge token to the provider: `POST /challenge`
3. Provider must return the merkle proof for that chunk within the timeout
4. Coordinator verifies the proof against the stored merkle root and
   replica commitment

### Scoring

Each provider has a score from 0.0 to 1.0:

- **Start:** 1.0 (full trust)
- **Challenge pass:** Score recovers toward 1.0 (configurable recovery rate)
- **Challenge fail:** Score decays (configurable decay rate)
- **Score = 0:** Provider is evicted from object assignments

Scores affect provider selection for new uploads (higher-scored providers
are preferred) and future payment calculations.

### Object health states

| State | Meaning |
|-------|---------|
| `pending` | Uploaded but not yet audited |
| `verified` | Most recent challenge passed on all providers |
| `degraded` | A provider failed a challenge and was evicted. Object has fewer replicas than the target. Replicator will attempt to restore replication. |

### Replication

The default replication factor is 3. When a provider is evicted (score too
low or challenge failure), the replicator automatically copies the object
to another healthy provider to restore the target replica count.

## Token authentication

All data operations (upload, download, challenge, replication) require a
token signed by the coordinator's Ed25519 private key.

### Token format

Tokens are JWTs containing:

- `merkle_root`: which object this token authorizes access to
- `provider_id`: which provider can use this token
- `account_id`: which account owns this object
- `type`: upload, download, or challenge
- `iat` / `exp`: issued-at and expiration timestamps

### Verification flow

1. Coordinator issues token: signs with Ed25519 private key
2. Provider receives request with `Authorization: Bearer {token}`
3. Provider verifies signature using the coordinator's public key
   (fetched from `GET /public-key` on startup)
4. Provider checks token type, merkle root, provider ID, and expiration
5. Request proceeds only if all checks pass

Forged or expired tokens are rejected. A provider cannot serve data
to an unauthorized party.

## What the coordinator can and cannot do

### Can

- Issue upload/download/challenge tokens (controls who accesses what)
- Select which providers store each object
- Run challenge cycles to verify provider integrity
- Evict underperforming providers and trigger replication
- Wrap/unwrap encryption keys (KMS)
- Track usage and calculate payment accruals

### Cannot

- Access stored data (providers hold ciphertext, coordinator holds the wrapped key but not the ciphertext)
- Execute code on provider machines
- Access files outside the provider's data directory
- Modify stored data (providers verify merkle proofs independently)
- Decrypt data without a valid account API key (KMS unwrap requires account auth)

## What providers can and cannot see

### Can see

- Ciphertext bytes (opaque, encrypted)
- Merkle root and chunk hashes (cryptographic identifiers, not content)
- File size
- Which coordinator issued the tokens
- Challenge requests (random chunk index + nonce)

### Cannot see

- Plaintext file content (encrypted with per-file AES-256-GCM key)
- Encryption keys (wrapped by coordinator KMS, never sent to providers)
- File names or metadata (stored on coordinator, not provider)
- Other providers' data or identities
- Account information (only the account_id in the token, not credentials)

## Provider identity

Each provider generates an Ed25519 keypair on first startup:

- **Private key:** Stored locally at `{data_dir}/.identity_ed25519` (permissions 0600)
- **Public key:** Sent to coordinator during registration (hex-encoded 32 bytes)
- **Purpose:** Uniquely identifies the provider. Used for idempotent re-registration
  (same pubkey + address = same provider, not a duplicate).

Loss of the private key means loss of the provider's identity. The provider
would need to re-register with a new identity.

## Network topology

```
Users/Apps
    |
    | HTTPS (API key auth)
    v
Coordinator (Akash)
    |
    | HTTPS (signed tokens)
    v
Providers (operator machines)
    |
    | Tailscale Funnel or Akash ingress
    v
Public internet
```

- User -> Coordinator: HTTPS, authenticated by API key
- Coordinator -> Provider: HTTPS (via Tailscale Funnel or direct), authenticated by signed tokens
- Provider -> Coordinator: HTTPS, for registration and heartbeat (no auth required)
- Provider -> Provider: HTTPS, for replication (authenticated by coordinator-signed tokens)

No direct user-to-provider connections without a coordinator-issued token.
