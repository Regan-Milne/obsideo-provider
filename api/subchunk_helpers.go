package api

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// ── Sub-chunk Merkle Primitive (compact proofs, proof_version 4) ─────────────
//
// This mirrors coordinator/proof/subchunk.go so the provider can answer a
// (chunk, block) challenge with the raw block bytes plus the bottom-up sibling
// hashes. Where the object-level tree (challenge_helpers.go) commits to 1 MiB
// chunks, this tree commits to the SubChunkBlockSize-byte blocks *inside* a
// single chunk. The per-chunk root is the "seal".
//
// LOAD-BEARING PROPERTY — cross-side determinism. The provider and coordinator
// build this tree independently from the same bytes and MUST arrive at
// byte-identical seals, leaves and sibling paths. Everything here is a pure
// function of its inputs. As with challenge_helpers.go, the convention is not
// re-derived: the block leaf reuses chunkHashV1 + sha3Sum512, and the fold /
// sibling walk reuse the exact next-power-of-2 zero-padding and SHA3-512
// pair-hashing the object-level tree already uses (computeMerkleProof). The
// sub-chunk sibling walk is in fact structurally identical to
// computeMerkleProof, so it is reused verbatim rather than copied.
// subchunk_golden_test.go pins the whole thing against vectors emitted by the
// coordinator's own primitive.
//
// The provider is stateless: it holds no seal. On every v4 challenge it rebuilds
// the tree from the chunk bytes, so only splitting, leaf hashing and sibling
// generation are on the hot path. buildSubChunkSeal exists to complete the
// faithful mirror (it is the coordinator's BuildSubChunkSeal) and is exercised
// by the golden cross-side test; the handler does not call it.

// subChunkBlockSize is the fixed block granularity within a chunk. A 1 MiB chunk
// splits into up to 256 blocks of this size; the final block of the final chunk
// may be shorter. Must match coordinator/proof.SubChunkBlockSize.
const subChunkBlockSize = 4096

// subChunkBlockCount returns the number of blocks a chunk of chunkLen bytes
// splits into (ceil division). Returns 0 for an empty chunk. Mirrors
// coordinator/proof.SubChunkBlockCount.
func subChunkBlockCount(chunkLen int) int {
	if chunkLen <= 0 {
		return 0
	}
	return (chunkLen + subChunkBlockSize - 1) / subChunkBlockSize
}

// splitSubChunkBlocks divides a chunk into subChunkBlockSize-byte blocks. The
// final block may be shorter. Blocks are sub-slices of chunk (no copy).
func splitSubChunkBlocks(chunk []byte) [][]byte {
	n := subChunkBlockCount(len(chunk))
	blocks := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := i * subChunkBlockSize
		end := start + subChunkBlockSize
		if end > len(chunk) {
			end = len(chunk)
		}
		blocks[i] = chunk[start:end]
	}
	return blocks
}

// subChunkLeaf computes the merkle leaf for a single block. It is the exact
// object-level convention (challenge_helpers.go) applied at block granularity:
//
//	leaf = SHA3-512( SHA-256(fmt.Sprintf("%d%x", blockIndex, block)) )
//
// chunkHashV1 binds the position; sha3Sum512 is the wealdtech pre-hash step.
func subChunkLeaf(blockIndex int, block []byte) []byte {
	return sha3Sum512(chunkHashV1(blockIndex, block))
}

// subChunkLeaves builds the leaf level for every block of a chunk.
func subChunkLeaves(chunk []byte) [][]byte {
	blocks := splitSubChunkBlocks(chunk)
	leaves := make([][]byte, len(blocks))
	for i, b := range blocks {
		leaves[i] = subChunkLeaf(i, b)
	}
	return leaves
}

// generateSubChunkSiblings returns the raw bytes of block blockIndex together
// with the bottom-up sibling hashes needed to recompute the seal. A single-block
// chunk yields empty siblings. Mirrors coordinator/proof.GenerateSubChunkProof;
// the sibling walk is computeMerkleProof (identical convention), fed sub-chunk
// leaves.
func generateSubChunkSiblings(chunk []byte, blockIndex int) (block []byte, siblings []string, err error) {
	if len(chunk) == 0 {
		return nil, nil, fmt.Errorf("sub-chunk proof: chunk is empty")
	}
	blocks := splitSubChunkBlocks(chunk)
	if blockIndex < 0 || blockIndex >= len(blocks) {
		return nil, nil, fmt.Errorf("sub-chunk proof: blockIndex %d out of range [0, %d)", blockIndex, len(blocks))
	}

	leaves := make([][]byte, len(blocks))
	for i, b := range blocks {
		leaves[i] = subChunkLeaf(i, b)
	}

	return blocks[blockIndex], computeMerkleProof(leaves, blockIndex), nil
}

// buildSubChunkSeal builds the sub-chunk merkle tree over the blocks of chunk
// and returns the hex-encoded SHA3-512 root ("seal"). Mirrors
// coordinator/proof.BuildSubChunkSeal. The handler never needs this — the
// provider is stateless — but it completes the faithful mirror and is asserted
// against the coordinator's own seals in subchunk_golden_test.go.
func buildSubChunkSeal(chunk []byte) (string, error) {
	if len(chunk) == 0 {
		return "", fmt.Errorf("sub-chunk seal: chunk is empty")
	}
	root := buildSubChunkRoot(subChunkLeaves(chunk))
	if root == nil {
		return "", fmt.Errorf("sub-chunk seal: nil root")
	}
	return hex.EncodeToString(root), nil
}

// buildSubChunkRoot folds a leaf level to its SHA3-512 root using the same
// next-power-of-2 zero-padding and pair hashing as computeMerkleProof (and the
// coordinator's buildMerkleRoot). Single leaf → that leaf; empty → nil.
func buildSubChunkRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	target := nextPow2(len(leaves))
	level := make([][]byte, target)
	copy(level, leaves)
	for i := len(leaves); i < target; i++ {
		level[i] = make([]byte, hashLen) // SHA3-512 zero-hash padding
	}

	for len(level) > 1 {
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha3.New512()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}
