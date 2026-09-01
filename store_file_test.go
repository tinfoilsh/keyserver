package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{"models/private":{"key":"secret-value"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.Read(context.Background(), &SecretRef{Path: "models/private", Field: "key"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "secret-value" {
		t.Fatalf("Read = %q", value)
	}
}

func TestFileStoreRejectsInvalidInput(t *testing.T) {
	if _, err := newFileStore(""); err == nil {
		t.Fatal("empty path accepted")
	}
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileStore(path); err == nil {
		t.Fatal("empty secret map accepted")
	}
}
