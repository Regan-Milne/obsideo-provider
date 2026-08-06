package store

import (
	"bytes"
	"strings"
	"testing"
)

// Golden vectors copied VERBATIM from s3-gateway/crypto/merkle_test.go
// (generated 2026-06-12, stage 0 of the gateway streaming work). Object
// identity on the network IS the merkle root: the provider MUST reproduce
// these exact roots or it will reject every object the gateway/SDK uploaded
// (verify-at-close) and become unaddressable. Do not regenerate these to make
// a failing test pass — a mismatch means store/merkle.go is wrong, not the
// vectors. These are the same vectors the live gateway is pinned to, so a
// match here proves byte-identical content addressing across both binaries.
//
// Inputs are patternBytes(n): b[i] = byte(i % 251). 251 is prime so the
// pattern never aligns with the 1 MiB chunk boundary.
var merkleGoldens = []struct {
	name       string
	size       int
	chunkCount int
	root       string
	firstChunk string
	lastChunk  string
}{
	{
		name:       "single-byte",
		size:       1,
		chunkCount: 1,
		root:       "c8cdadbaedc6c6c7f4381b06f582280bc0a47fe34b4b0c336929d98cb604c0b746b8f2b783642e97893f82869a01be191fab769f084fbef0d7033a135c84f451",
		firstChunk: "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
		lastChunk:  "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
	},
	{
		name:       "small-19-bytes",
		size:       19,
		chunkCount: 1,
		root:       "e25a392c1f21d2fe69be1e8d01b015a934170d95c48af1e34dc81bf529bdb597cf37bbf36e4cc6809a4cb51281bf5718542f781716dc0dcd85174266632452d1",
		firstChunk: "b160cec05f4fbdbb120642c8cd6d49cf0fac1c2e5aff1bf8e2227a33cd4b0d25",
		lastChunk:  "b160cec05f4fbdbb120642c8cd6d49cf0fac1c2e5aff1bf8e2227a33cd4b0d25",
	},
	{
		// Exactly one chunk: root is the SHA3-512 leaf itself, no tree built.
		name:       "exactly-1MiB",
		size:       1048576,
		chunkCount: 1,
		root:       "7323c4a9f3e2356b73aa08309a8cc8105d381a068bfc651f87cc0c03e560be67208716ae3b3bc84962b45d9ce1952ccf9c9680c7a7ab8fcb0b005c04ab8cac16",
		firstChunk: "490c2e0f350c974c8755be81a88d63027dfb181530381b7ebe7811db2896b1ea",
		lastChunk:  "490c2e0f350c974c8755be81a88d63027dfb181530381b7ebe7811db2896b1ea",
	},
	{
		// One byte over the boundary: 2 chunks, first time the tree is built.
		name:       "1MiB-plus-1",
		size:       1048577,
		chunkCount: 2,
		root:       "07db6ef153f7fcce73ee0d60cb120ba292f85403bf4284c0915fd6276982159c2da875e60828e9bdda66768407b25186e6345a8501df1c53b1bf878ad6fb5525",
		firstChunk: "490c2e0f350c974c8755be81a88d63027dfb181530381b7ebe7811db2896b1ea",
		lastChunk:  "1dfacb2ea5a03e0a915999e03b5a56196f1b1664d2f768d1b7eff60ac059789d",
	},
	{
		// 3 chunks: exercises zero-hash padding to the next power of 2 (4 leaves).
		name:       "3MiB-padded-tree",
		size:       3145728,
		chunkCount: 3,
		root:       "962859d2468d1782fc8014f825175ffdc8e8ff21e48a14d3df891f749e14bf8e4328d25a7f38aa6572f15c87bdb3b88ce9f8fe2509a85d95fc5db65d741cd7cc",
		firstChunk: "490c2e0f350c974c8755be81a88d63027dfb181530381b7ebe7811db2896b1ea",
		lastChunk:  "1e0b60d3e58933a0c6ee245890456224c01a448881e597c706363af9bd78adce",
	},
	{
		// Production-shaped: multi-chunk with a ragged tail (5 MiB + 12345 bytes,
		// 6 chunks padded to 8 leaves).
		name:       "5MiB-ragged-tail",
		size:       5255225,
		chunkCount: 6,
		root:       "19208e9ed2d8dbc2872536126f978b6786dd32dc65d8aabaf2e6b153b5c19a59134530ff3b60afd5985a3df96d8aff514c7c74e67350d04b67c775f9421842a1",
		firstChunk: "490c2e0f350c974c8755be81a88d63027dfb181530381b7ebe7811db2896b1ea",
		lastChunk:  "c9ae518a30842ee96bcbde39b1eeb81478cb0b86e9b86d51083dfbc5921a1fa2",
	},
}

// patternBytes returns n deterministic bytes: b[i] = byte(i % 251).
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func TestBuildMerkleTreeGoldenVectors(t *testing.T) {
	for _, g := range merkleGoldens {
		t.Run(g.name, func(t *testing.T) {
			root, hashes, err := BuildMerkleTree(patternBytes(g.size))
			if err != nil {
				t.Fatalf("BuildMerkleTree(%d bytes): %v", g.size, err)
			}
			if len(hashes) != g.chunkCount {
				t.Errorf("chunk count = %d, want %d", len(hashes), g.chunkCount)
			}
			if root != g.root {
				t.Errorf("root mismatch for %d bytes:\n got %s\nwant %s", g.size, root, g.root)
			}
			if hashes[0] != g.firstChunk {
				t.Errorf("first chunk hash mismatch:\n got %s\nwant %s", hashes[0], g.firstChunk)
			}
			if hashes[len(hashes)-1] != g.lastChunk {
				t.Errorf("last chunk hash mismatch:\n got %s\nwant %s", hashes[len(hashes)-1], g.lastChunk)
			}
		})
	}
}

// TestTreeBuilderMatchesBuildMerkleTree is the identity invariant: the
// streaming TreeBuilder must produce exactly the same root and chunk hashes
// as the buffered BuildMerkleTree, for every golden size AND under adversarial
// write segmentation (1-byte writes, odd-sized writes that straddle the 1 MiB
// chunk boundary). This is what lets PutStream hash-while-spooling and still
// verify-at-close against the network identity.
func TestTreeBuilderMatchesBuildMerkleTree(t *testing.T) {
	segmentations := []int{1, 7, 4096, 1048575, 1048576, 1048577, 3_000_000}
	for _, g := range merkleGoldens {
		data := patternBytes(g.size)
		wantRoot, wantHashes, err := BuildMerkleTree(data)
		if err != nil {
			t.Fatalf("%s: BuildMerkleTree: %v", g.name, err)
		}
		for _, seg := range segmentations {
			t.Run(g.name+"/seg="+itoa(seg), func(t *testing.T) {
				tb := NewTreeBuilder()
				for off := 0; off < len(data); off += seg {
					end := off + seg
					if end > len(data) {
						end = len(data)
					}
					n, _ := tb.Write(data[off:end])
					if n != end-off {
						t.Fatalf("Write returned %d, want %d", n, end-off)
					}
				}
				gotRoot, gotHashes, err := tb.Finish()
				if err != nil {
					t.Fatalf("Finish: %v", err)
				}
				if tb.Size() != int64(len(data)) {
					t.Errorf("Size() = %d, want %d", tb.Size(), len(data))
				}
				if gotRoot != wantRoot {
					t.Errorf("root mismatch:\n got %s\nwant %s", gotRoot, wantRoot)
				}
				if len(gotHashes) != len(wantHashes) {
					t.Fatalf("chunk count %d, want %d", len(gotHashes), len(wantHashes))
				}
				for i := range gotHashes {
					if gotHashes[i] != wantHashes[i] {
						t.Errorf("chunk hash %d mismatch:\n got %s\nwant %s", i, gotHashes[i], wantHashes[i])
					}
				}
			})
		}
	}
}

func TestBuildMerkleTreeEmptyRejected(t *testing.T) {
	if _, _, err := BuildMerkleTree(nil); err == nil {
		t.Error("BuildMerkleTree(nil) should error")
	}
	if _, _, err := BuildMerkleTree([]byte{}); err == nil {
		t.Error("BuildMerkleTree(empty) should error")
	}
	tb := NewTreeBuilder()
	if _, _, err := tb.Finish(); err == nil {
		t.Error("TreeBuilder.Finish() on empty should error")
	}
}

// TestChunkSizeFrozen pins the 1 MiB chunk size. The coordinator hard-rejects
// any other value, so this constant is part of the wire contract.
func TestChunkSizeFrozen(t *testing.T) {
	if DefaultChunkSize != 1048576 {
		t.Fatalf("DefaultChunkSize = %d; 1 MiB is frozen by the coordinator wire contract", DefaultChunkSize)
	}
}

// TestRootFormat pins the root encoding: 128-char lowercase hex (SHA3-512).
func TestRootFormat(t *testing.T) {
	root, _, err := BuildMerkleTree([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 128 {
		t.Errorf("root length = %d, want 128 hex chars", len(root))
	}
	if root != strings.ToLower(root) {
		t.Error("root must be lowercase hex")
	}
}

// TestChunkHashesMatchBuildIndex pins that the merkle chunk hashes equal the
// challenge index's chunk hashes for a 1 MiB index — they MUST, because
// challenge.go reconstructs the merkle proof from the stored index, and the
// coordinator verifies that proof against the registered root. If these ever
// diverge, challenges silently fail for multi-chunk objects.
func TestChunkHashesMatchBuildIndex(t *testing.T) {
	data := patternBytes(3145728) // 3 chunks
	_, merkleHashes, err := BuildMerkleTree(data)
	if err != nil {
		t.Fatal(err)
	}
	idx := buildIndex(data, DefaultChunkSize)
	if idx.TotalChunks != len(merkleHashes) {
		t.Fatalf("index chunks %d != merkle chunks %d", idx.TotalChunks, len(merkleHashes))
	}
	for i := range merkleHashes {
		if idx.ChunkHashes[i] != merkleHashes[i] {
			t.Errorf("chunk %d: index hash %s != merkle hash %s", i, idx.ChunkHashes[i], merkleHashes[i])
		}
	}
}

// itoa avoids importing strconv just for the subtest name.
func itoa(n int) string {
	var b bytes.Buffer
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i := len(digits) - 1; i >= 0; i-- {
		b.WriteByte(digits[i])
	}
	return b.String()
}
