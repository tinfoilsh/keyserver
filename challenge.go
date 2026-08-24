package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

const (
	nonceTTL      = 2 * time.Minute
	maxLiveNonces = 65536
)

// nonceStore issues single-use challenge nonces. Bounded and expiring, so
// unauthenticated /challenge traffic cannot grow memory without limit and a
// captured nonce cannot be redeemed later.
type nonceStore struct {
	mu     sync.Mutex
	now    func() time.Time
	issued map[string]time.Time
}

func newNonceStore() *nonceStore {
	return &nonceStore{now: time.Now, issued: map[string]time.Time{}}
}

// Issue returns a fresh lowercase-hex nonce of envelope.NonceSize bytes.
func (s *nonceStore) Issue() (string, error) {
	nonce, err := envelope.RandomNonce()
	if err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	encoded := hex.EncodeToString(nonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.issued) >= maxLiveNonces {
		return "", fmt.Errorf("challenge capacity exhausted")
	}
	s.issued[encoded] = s.now().Add(nonceTTL)
	return encoded, nil
}

// Consume redeems an issued, unexpired nonce exactly once.
func (s *nonceStore) Consume(encoded string) ([]byte, error) {
	nonce, err := hex.DecodeString(encoded)
	if err != nil || len(nonce) != envelope.NonceSize {
		return nil, fmt.Errorf("malformed nonce")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.issued[encoded]
	if !ok {
		return nil, fmt.Errorf("nonce was not issued or was already used")
	}
	delete(s.issued, encoded)
	if s.now().After(expiry) {
		return nil, fmt.Errorf("nonce expired")
	}
	return nonce, nil
}

func (s *nonceStore) sweepLocked() {
	now := s.now()
	for nonce, expiry := range s.issued {
		if now.After(expiry) {
			delete(s.issued, nonce)
		}
	}
}

// handleChallenge issues the nonce a caller must bind into its fresh v3
// attestation document. The response shape is exact: the client rejects
// unknown fields.
func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nonce, err := s.nonces.Issue()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
}
