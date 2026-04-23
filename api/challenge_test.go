package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Regan-Milne/obsideo-provider/store"
)

type challengeResponseBody struct {
	ChallengeID     string `json:"challenge_id"`
	ChunkHash       string `json:"chunk_hash"`
	TotalChunkCount int    `json:"total_chunk_count"`
}

func TestHandleChallengeSupportsCanonicalChunkSize(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	merkle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	data := bytes.Repeat([]byte("a"), (2*store.DefaultChunkSize)+17)
	if err := st.Put(merkle, data, store.DefaultChunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}

	idx, err := st.GetIndex(merkle)
	if err != nil {
		t.Fatalf("GetIndex: %v", err)
	}

	server := New(st, nil, nil)
	body, err := json.Marshal(map[string]any{
		"challenge_id": "challenge-new",
		"merkle":       merkle,
		"chunk_index":  1,
		"nonce":        "00",
		"expires_at":   1,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	res := httptest.NewRecorder()
	server.handleChallenge(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}

	var got challengeResponseBody
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.TotalChunkCount != idx.TotalChunks {
		t.Fatalf("total chunks = %d, want %d", got.TotalChunkCount, idx.TotalChunks)
	}
	if got.ChunkHash != idx.ChunkHashes[1] {
		t.Fatalf("chunk hash mismatch: got %s want %s", got.ChunkHash, idx.ChunkHashes[1])
	}
}

func TestHandleChallengeSupportsLegacyChunkSize(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	const legacyChunkSize = 10240
	merkle := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	data := bytes.Repeat([]byte("b"), (3*legacyChunkSize)+11)
	if err := st.Put(merkle, data, legacyChunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}

	idx, err := st.GetIndex(merkle)
	if err != nil {
		t.Fatalf("GetIndex: %v", err)
	}

	server := New(st, nil, nil)
	body, err := json.Marshal(map[string]any{
		"challenge_id": "challenge-legacy",
		"merkle":       merkle,
		"chunk_index":  2,
		"nonce":        "00",
		"expires_at":   1,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	res := httptest.NewRecorder()
	server.handleChallenge(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}

	var got challengeResponseBody
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.TotalChunkCount != idx.TotalChunks {
		t.Fatalf("total chunks = %d, want %d", got.TotalChunkCount, idx.TotalChunks)
	}
	if got.ChunkHash != idx.ChunkHashes[2] {
		t.Fatalf("chunk hash mismatch: got %s want %s", got.ChunkHash, idx.ChunkHashes[2])
	}
}
