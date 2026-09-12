package store

// patternBytes returns n deterministic bytes: b[i] = byte(i % 251).
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}
