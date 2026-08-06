package store

// Merkle tree construction, identical to the Obsideo SDK, the s3-gateway
// (s3-gateway/crypto/merkle.go + stream.go), and the coordinator verifier.
// The merkle root IS an object's network identity, so this code MUST
// reproduce the same roots as every other implementation — it is pinned to
// the shared golden vectors in merkle_test.go (copied verbatim from the
// gateway). Do not "fix" a golden-vector failure by regenerating the
// vectors: a mismatch means this code is wrong, not the vectors.
//
// Algorithm:
//  1. Split data into 1 MiB chunks (DefaultChunkSize).
//  2. For each chunk: SHA-256("{index}{hex_of_chunk_bytes}") -> hex string.
//     (This is exactly buildIndex's chunk-hash formula; the index and the
//     merkle leaves are computed from the same chunk hashes.)
//  3. For each chunk hash: SHA3-512(raw_bytes_of_hex_hash) -> 64-byte leaf.
//  4. Pad leaves to next power of 2 with zero-hashes (64 bytes of 0x00).
//  5. Build binary tree bottom-up: parent = SHA3-512(left || right).
//  6. Root is a 64-byte SHA3-512 hash, output as a 128-char hex string.
//
// A single chunk is a special case: the root is the leaf itself (no tree).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"

	"golang.org/x/crypto/sha3"
)

// merkleLeafLen is the byte length of a SHA3-512 leaf / tree node.
const merkleLeafLen = 64

// BuildMerkleTree computes the chunk hashes and merkle root for data, using
// the frozen 1 MiB chunk size. Returns the root as a hex string and the
// per-chunk hashes as hex strings. Errors on empty input, exactly like the
// gateway's BuildTree (an empty object has no defined network identity).
//
// This is the buffered reference implementation; PutStream computes the
// identical result without ever holding the object in memory via TreeBuilder.
func BuildMerkleTree(data []byte) (rootHex string, chunkHashes []string, err error) {
	if len(data) == 0 {
		return "", nil, fmt.Errorf("cannot build tree from empty data")
	}

	chunkCount := (len(data) + DefaultChunkSize - 1) / DefaultChunkSize
	chunkHashes = make([]string, chunkCount)
	for i := 0; i < chunkCount; i++ {
		start := i * DefaultChunkSize
		end := start + DefaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		h := sha256.Sum256([]byte(fmt.Sprintf("%d%x", i, chunk)))
		chunkHashes[i] = hex.EncodeToString(h[:])
	}

	rootHex, err = treeFromChunkHashes(chunkHashes)
	if err != nil {
		return "", nil, err
	}
	return rootHex, chunkHashes, nil
}

// treeFromChunkHashes builds the merkle root from already-computed chunk
// hashes (steps 3-6). Shared by BuildMerkleTree and TreeBuilder so the
// buffered and streaming paths cannot diverge.
func treeFromChunkHashes(chunkHashes []string) (string, error) {
	if len(chunkHashes) == 0 {
		return "", fmt.Errorf("cannot build tree from zero chunks")
	}

	// SHA3-512 each chunk hash to get the 64-byte leaves.
	leaves := make([][]byte, len(chunkHashes))
	for i, ch := range chunkHashes {
		raw, err := hex.DecodeString(ch)
		if err != nil {
			return "", fmt.Errorf("decode chunk hash %d: %w", i, err)
		}
		h := sha3.Sum512(raw)
		leaves[i] = h[:]
	}

	// Single leaf: the root is the leaf itself, no tree built.
	if len(leaves) == 1 {
		return hex.EncodeToString(leaves[0]), nil
	}

	// Pad to the next power of 2 with zero-hashes.
	size := nextPow2(len(leaves))
	for len(leaves) < size {
		leaves = append(leaves, make([]byte, merkleLeafLen))
	}

	// Build bottom-up: parent = SHA3-512(left || right).
	level := leaves
	for len(level) > 1 {
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			combined := make([]byte, 0, 2*merkleLeafLen)
			combined = append(combined, level[i]...)
			combined = append(combined, level[i+1]...)
			h := sha3.Sum512(combined)
			next = append(next, h[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0]), nil
}

func nextPow2(n int) int {
	v := 1
	for v < n {
		v <<= 1
	}
	return v
}

// TreeBuilder computes the same root as BuildMerkleTree without ever holding
// the object in memory: bytes are fed incrementally via Write and only the
// running chunk hash plus the list of finished chunk hashes (one 64-char
// string per MiB) are retained. This is what lets PutStream hash-while-
// spooling to disk on streaming ingest.
//
// Mirrors s3-gateway/crypto/stream.go::TreeBuilder. Identity invariant: for
// any input, Write-ing it in any segmentation then calling Finish MUST
// produce exactly BuildMerkleTree's output — the tree step is literally the
// shared treeFromChunkHashes, and the chunk-hash step is pinned equivalent
// by the golden vectors.
type TreeBuilder struct {
	chunkHashes []string
	chunkHash   hash.Hash // running SHA-256 of "{index}{hex_of_chunk_bytes}"
	chunkFill   int       // bytes of the current 1 MiB chunk consumed so far
	total       int64
	hexScratch  []byte
}

// NewTreeBuilder returns a ready-to-use streaming merkle builder.
func NewTreeBuilder() *TreeBuilder {
	return &TreeBuilder{hexScratch: make([]byte, 64*1024)}
}

// Write implements io.Writer. Never returns an error.
func (b *TreeBuilder) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if b.chunkHash == nil {
			// New chunk: the hash input starts with the decimal chunk index.
			b.chunkHash = sha256.New()
			b.chunkHash.Write([]byte(strconv.Itoa(len(b.chunkHashes))))
		}

		take := DefaultChunkSize - b.chunkFill
		if take > len(p) {
			take = len(p)
		}

		// Chunk bytes enter the hash hex-encoded (matching the "%d%x"
		// formula). Encode through a fixed scratch buffer so arbitrarily
		// large writes stay constant-memory.
		seg := p[:take]
		for len(seg) > 0 {
			m := len(b.hexScratch) / 2
			if m > len(seg) {
				m = len(seg)
			}
			hex.Encode(b.hexScratch[:2*m], seg[:m])
			b.chunkHash.Write(b.hexScratch[:2*m])
			seg = seg[m:]
		}

		b.chunkFill += take
		b.total += int64(take)
		p = p[take:]

		if b.chunkFill == DefaultChunkSize {
			b.finishChunk()
		}
	}
	return n, nil
}

func (b *TreeBuilder) finishChunk() {
	b.chunkHashes = append(b.chunkHashes, hex.EncodeToString(b.chunkHash.Sum(nil)))
	b.chunkHash = nil
	b.chunkFill = 0
}

// Size returns the number of bytes written so far.
func (b *TreeBuilder) Size() int64 { return b.total }

// Finish closes the final partial chunk and returns the merkle root and the
// per-chunk hashes. Errors on empty input, exactly like BuildMerkleTree.
func (b *TreeBuilder) Finish() (rootHex string, chunkHashes []string, err error) {
	if b.total == 0 {
		return "", nil, fmt.Errorf("cannot build tree from empty data")
	}
	if b.chunkFill > 0 {
		b.finishChunk()
	}
	rootHex, err = treeFromChunkHashes(b.chunkHashes)
	if err != nil {
		return "", nil, err
	}
	return rootHex, b.chunkHashes, nil
}
