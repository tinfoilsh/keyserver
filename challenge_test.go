package main

import (
	"strings"
	"testing"
	"time"
)

func TestNonceSingleUse(t *testing.T) {
	store := newNonceStore()
	nonce, err := store.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if nonce != strings.ToLower(nonce) || len(nonce) != 64 {
		t.Fatalf("nonce = %q", nonce)
	}
	if _, err := store.Consume(nonce); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, err := store.Consume(nonce); err == nil {
		t.Fatal("nonce consumed twice")
	}
}

func TestNonceExpiry(t *testing.T) {
	store := newNonceStore()
	now := time.Now()
	store.now = func() time.Time { return now }
	nonce, err := store.Issue()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(nonceTTL + time.Second)
	if _, err := store.Consume(nonce); err == nil {
		t.Fatal("expired nonce consumed")
	}
}

func TestNonceRejectsMalformed(t *testing.T) {
	store := newNonceStore()
	for _, nonce := range []string{"", "zz", strings.Repeat("00", 16), strings.Repeat("00", 33)} {
		if _, err := store.Consume(nonce); err == nil {
			t.Fatalf("malformed nonce %q consumed", nonce)
		}
	}
}
