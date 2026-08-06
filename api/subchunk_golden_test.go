package api

import (
	"encoding/hex"
	"testing"
)

// GOLDEN CROSS-SIDE VECTORS — the load-bearing test for compact proofs (v4).
//
// These constants were emitted by a throwaway generator run against the
// coordinator's OWN reference primitive (github.com/obsideo/coordinator/proof:
// BuildSubChunkSeal / GenerateSubChunkProof), self-verified inside the
// generator with proof.VerifySubChunkProof before printing. The generator
// source is committed at ../testdata/subchunk_golden_gen.go (build-ignored:
// testdata is skipped by the go tool). It was run as:
//
//	cd <worktree>/coordinator
//	go run <worktree>/provider-clean/testdata/subchunk_golden_gen.go
//
// Each chunk is built by goldenChunk(size), which MUST stay byte-identical to
// the generator's makeChunk (b[i] = byte((i*31+7)&0xff)). This test asserts the
// provider's MIRRORED primitive (buildSubChunkSeal / subChunkLeaf /
// generateSubChunkSiblings) reproduces the coordinator's seals, block-leaf
// hashes and sibling lists exactly. A failure here means cross-side divergence
// — the one bug class compact proofs cannot tolerate.

// goldenChunk builds a deterministic chunk. Byte-identical to the generator's
// makeChunk; do not change without regenerating every constant below.
func goldenChunk(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

type goldenBlock struct {
	index    int
	blockLen int
	hash     string
	siblings []string
}

type goldenChunkVec struct {
	name        string
	size        int
	totalBlocks int
	seal        string
	blocks      []goldenBlock
}

var goldenVectors = []goldenChunkVec{
	{
		name:        "OneMiB",
		size:        1 << 20,
		totalBlocks: 256,
		seal:        "bb14d9d9bb0f1795e3a7391abad84aa21c8fdaea8f145e6250a82e4a89d0cbcd41fa92663ad0b91f7ef4d1b69e04b8d6de28f40c91c00208e57fce99a17a57f9",
		blocks: []goldenBlock{
			{
				index:    0,
				blockLen: 4096,
				hash:     "09dc6b34872fc153502ecab2b4536c0d65594749dcf9b3230c8bbf1a6e83b61b6d01e300ecde310ea6e9b7414c5a0e4ba9d6194a399a88e16911cbf2d1682441",
				siblings: []string{
					"d2959c3fb31805c94344a5190c457dd2f4416c641f465210776580a24aeac94a848dff8e4d378ca8adf6b08bc5892b5c3a28789c6c5da032e51c1af19b3e3ab6",
					"1500650e53a1a8b6f98c4d9266ab563b2fc6fca148d7df980108ec014afe95e35d21d79903dbb06bd41acf0fb00ef957c127781436ff3678a405bac6034e6424",
					"da58db144739ac70c2baf07e01ec353b098d2720eb00bc2609bd7c09028d8f9645ad3726574ea3f2198100cacee47396a0bef52917a97b8c24f27a393a1ba378",
					"ced510828a78d27d2a9e7c3679c29865cb1dd033aa13fdeef77a915699f7c1e48fd4382bf74365fbc1d6601c68c1bf1d27e884dd7f1ad52353594bb0b7b6f89b",
					"59f76f52f1052333f94d5e5a9cb156e8257b6e2e0373f7d843327465207c2254fe993e1b684020269df0a57ab9531529342d5fb965d4055fd2e522a03e6ba686",
					"afd436cf0bcb9d1ea6d834533e46ad1363221997a6faef11fa7611c104707f2427562a396d92e999487c394e5ffe64a72b7026730d1b0d875a998b354c5db2bb",
					"850707f162838ddab1e4bf7f2e0210bccdd1c5d337caad76b5f6a6e255588a28aeaf7c23c5d0e5a93c5769a348d503729391a1b7a23f99cfe803729b1b03cb8d",
					"46f2c2cd1b3ed73a1be4c25b906bdf0f0b732c351070b0b4b86e6bc8c314edfe73b1fb8b4fb8d9233408203f7687db2ad895cbbd32567af30506e892ea3f19f2",
				},
			},
			{
				index:    255,
				blockLen: 4096,
				hash:     "d929c8980b1d0a4e3fd78b7b56aeb14fec5212ff09f5214f378318c0407c1577a87748351036dfdf9d0b3c3d34792b6d17ef70d88a2cb38afe6ad9b22003a576",
				siblings: []string{
					"db21a231d8d9b9a6fac1d6ba3fd53fcd53b9ab64031e953dddffc24130e32f41279c60bf343ad101380cd4d703bf6beed9eb629b4e8cbf1585bdb7e7ca5a6a8d",
					"db20c327c52589cee3408105177fdc1f76bef2841987e1cee46a6f6fac1718584b1309255b9ac072518aad56ef3128f4ebc50850208cc166fae4d4e68197f920",
					"75c82978cae7751ed8254eda30cec9696fe3e352bd2fbf3cbff5407974a4d2b60f9b80973cf52b355b43eb8c8a87c88c578903db134a096ff7441e48d16289c8",
					"894754a112ff6019ee659501a09f5f398c4be109f7459f3708d1a7ef2d694cefaf7d47ce4e546e871da64c1b87c202026c47000644ea3ca5ad9aba7a3b0ceeb8",
					"993527e3c8da1e4659793059306968f2485bb32cc5bd0d762e0fe133c4b258a0afb609018553d96526254e473a49aa5605ba2873f05420951965327425d09181",
					"aeb91c13a9fe5e95aa06dfce5d6ea6e27955a02013e7df7b88fdc558a03a3428ecac7f9b527cf9ea47c113c70c51f8f9d1854561ea12082daeb99aae32ffe095",
					"6fe969da7bd677aa1c5f376c1e604b5a53bd63cf879d99a1059e5773b5709c256b4caedcc7445e70b8925dd60d68e40128fe3ea8581848ac0afa0e1e7bfb99e7",
					"82e399599f1f8f616c14dea21ab7ab891a6dbb16c7e81b8577535217b291e9a8dcd739c56770b9f2a6ebfb6d2449e8f6d0da047f05e54e62516c9d2a0e9b3f23",
				},
			},
		},
	},
	{
		name:        "TenThousand",
		size:        10000,
		totalBlocks: 3,
		seal:        "77f495dc9b95adaa1d1b31f441ce3d33254897e963a1f6c9d426b85477c845fbcd7c87e4ec598529b00f11a0a7f618772cfda5f0f8bd84f3c74e36e8b174c5ee",
		blocks: []goldenBlock{
			{
				index:    0,
				blockLen: 4096,
				hash:     "09dc6b34872fc153502ecab2b4536c0d65594749dcf9b3230c8bbf1a6e83b61b6d01e300ecde310ea6e9b7414c5a0e4ba9d6194a399a88e16911cbf2d1682441",
				siblings: []string{
					"d2959c3fb31805c94344a5190c457dd2f4416c641f465210776580a24aeac94a848dff8e4d378ca8adf6b08bc5892b5c3a28789c6c5da032e51c1af19b3e3ab6",
					"c9319ecefa31d4903bb456f2f195b0ed178be78ecb08cc088ff7211188f2cfeb70c45f889e76d681aa50651095c346379b2f2675b4120ed73a3107a9d825cbc0",
				},
			},
			{
				index:    2,
				blockLen: 1808,
				hash:     "7664f7bdf4c8fb23aa4589be653716e52b74331c56a1edbe42d3bb309c7a825b4fee2823079be99e64565e7f595f770812005ed391f0cd02ff80b73b076a7c5b",
				siblings: []string{
					"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"77678309a5bf6b0cd9f0b920c5105226e7d131f831859b684a9e9673a5b18b43d6eda4449ea02c1194d790a1868f9b88ef2bc22072096848912637db80db5ab1",
				},
			},
		},
	},
	{
		name:        "ExactBlock",
		size:        4096,
		totalBlocks: 1,
		seal:        "09dc6b34872fc153502ecab2b4536c0d65594749dcf9b3230c8bbf1a6e83b61b6d01e300ecde310ea6e9b7414c5a0e4ba9d6194a399a88e16911cbf2d1682441",
		blocks: []goldenBlock{
			{
				index:    0,
				blockLen: 4096,
				hash:     "09dc6b34872fc153502ecab2b4536c0d65594749dcf9b3230c8bbf1a6e83b61b6d01e300ecde310ea6e9b7414c5a0e4ba9d6194a399a88e16911cbf2d1682441",
				siblings: []string{},
			},
		},
	},
	{
		name:        "Hundred",
		size:        100,
		totalBlocks: 1,
		seal:        "966ec6684d208f3390a23784bcfbbee0942f4731595e9db0f29f160275f381f8e8c79ce10b070d467ef356b672be65c58a4b48138ed3498363b86f802750cb2b",
		blocks: []goldenBlock{
			{
				index:    0,
				blockLen: 100,
				hash:     "966ec6684d208f3390a23784bcfbbee0942f4731595e9db0f29f160275f381f8e8c79ce10b070d467ef356b672be65c58a4b48138ed3498363b86f802750cb2b",
				siblings: []string{},
			},
		},
	},
}

func TestSubChunkGoldenCrossSide(t *testing.T) {
	for _, vec := range goldenVectors {
		t.Run(vec.name, func(t *testing.T) {
			chunk := goldenChunk(vec.size)

			if got := subChunkBlockCount(len(chunk)); got != vec.totalBlocks {
				t.Fatalf("block count = %d, want %d", got, vec.totalBlocks)
			}

			// Seal: the whole-tree root must match the coordinator's byte-for-byte.
			seal, err := buildSubChunkSeal(chunk)
			if err != nil {
				t.Fatalf("buildSubChunkSeal: %v", err)
			}
			if seal != vec.seal {
				t.Fatalf("seal mismatch:\n got %s\nwant %s", seal, vec.seal)
			}

			for _, gb := range vec.blocks {
				block, siblings, err := generateSubChunkSiblings(chunk, gb.index)
				if err != nil {
					t.Fatalf("generateSubChunkSiblings(%d): %v", gb.index, err)
				}
				if len(block) != gb.blockLen {
					t.Errorf("block %d len = %d, want %d", gb.index, len(block), gb.blockLen)
				}

				// Block leaf hash must match the coordinator's.
				gotHash := hex.EncodeToString(subChunkLeaf(gb.index, block))
				if gotHash != gb.hash {
					t.Errorf("block %d leaf hash mismatch:\n got %s\nwant %s", gb.index, gotHash, gb.hash)
				}

				// Sibling list must match the coordinator's exactly (order + values).
				if len(siblings) != len(gb.siblings) {
					t.Fatalf("block %d sibling count = %d, want %d", gb.index, len(siblings), len(gb.siblings))
				}
				for i := range siblings {
					if siblings[i] != gb.siblings[i] {
						t.Errorf("block %d sibling[%d] mismatch:\n got %s\nwant %s", gb.index, i, siblings[i], gb.siblings[i])
					}
				}
			}
		})
	}
}
