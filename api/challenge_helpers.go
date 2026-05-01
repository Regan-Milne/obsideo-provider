package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const hashLen = 64

// chunkHashV1 matches coordinator/proof/verifier.go::chunkHashV1 and the
// SDK's leaf formula: SHA-256(fmt.Sprintf("%d%x", index, raw_bytes)).
func chunkHashV1(index int, rawBytes []byte) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d%x", index, rawBytes)
	return h.Sum(nil)
}

func sha3Sum512(data []byte) []byte {
	h := sha3.New512()
	h.Write(data)
	return h.Sum(nil)
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	v := 1
	for v < n {
		v <<= 1
	}
	return v
}

// computeMerkleProof builds the sibling list from leaf to root for the given
// leaf index. Zero-pads to next power of 2 to match the SDK's wealdtech-
// compatible tree construction.
func computeMerkleProof(leaves [][]byte, leafIndex int) []string {
	if len(leaves) <= 1 {
		return []string{}
	}

	target := nextPow2(len(leaves))
	level := make([][]byte, target)
	copy(level, leaves)
	for i := len(leaves); i < target; i++ {
		level[i] = make([]byte, hashLen)
	}

	var siblings []string
	idx := leafIndex
	for len(level) > 1 {
		if idx%2 == 0 {
			siblings = append(siblings, hex.EncodeToString(level[idx+1]))
		} else {
			siblings = append(siblings, hex.EncodeToString(level[idx-1]))
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha3.New512()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
		idx /= 2
	}
	return siblings
}
