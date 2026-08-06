package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// ProofSigDomain is the domain-separation prefix for provider proof-response
// signatures. Bumping the version string invalidates old signatures by design,
// so a verifier can never be tricked into accepting a signature minted under a
// different scheme.
const ProofSigDomain = "obsideo-proof-response-v1"

// ProofSigPayload builds the canonical byte string a provider signs (and a
// verifier reconstructs) for a challenge response. The signature binds the
// response to the exact challenge and to the exact bytes returned, so a
// signature cannot be replayed for a different challenge, a different chunk,
// or tampered data.
//
// Layout — newline-delimited, in fixed order:
//
//	obsideo-proof-response-v1\n
//	<provider_id>\n         (UUID; identifies WHICH provider — stops A's sig standing in for B)
//	<challenge_id>\n        (UUID; binds to this specific challenge)
//	<nonce>\n               (hex; the coord/client-chosen randomness)
//	<merkle_root>\n         (hex; the object)
//	<chunk_index>\n         (decimal; which chunk)
//	<block_index>\n         (decimal; compact-proof sub-block, 0 for v1 raw)
//	<proof_version>\n       (decimal)
//	<sha256(chunk_data_bytes) hex>   (digest of the RAW bytes returned, pre-base64)
//
// Every field is a UUID, hex string, or decimal integer, none of which can
// contain a newline, so newline-delimiting is unambiguous. The digest is over
// the raw chunk/block bytes (NOT their base64 text) so encoding choices never
// affect what is signed. This function is duplicated verbatim on the
// coordinator side (separate Go module); proofsig_golden_test.go pins the
// exact bytes so the two implementations cannot silently drift.
func ProofSigPayload(providerID, challengeID, nonce, merkleRoot string, chunkIndex, blockIndex, proofVersion int, chunkData []byte) []byte {
	digest := sha256.Sum256(chunkData)
	var b strings.Builder
	b.WriteString(ProofSigDomain)
	b.WriteByte('\n')
	b.WriteString(providerID)
	b.WriteByte('\n')
	b.WriteString(challengeID)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(merkleRoot)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(chunkIndex))
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(blockIndex))
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(proofVersion))
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(digest[:]))
	return []byte(b.String())
}
