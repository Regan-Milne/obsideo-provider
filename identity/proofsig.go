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

// ProofSigPayload builds the canonical byte string a provider signs for a
// challenge response. It binds the response to the exact challenge and to the
// exact bytes returned, so a signature cannot be replayed for a different
// challenge, a different chunk, or tampered data. The layout is fixed by the
// implementation below; the domain constant is versioned on purpose.
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
