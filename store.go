package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// secretStore reads one secret value by policy reference.
type secretStore interface {
	Read(ctx context.Context, ref *SecretRef) (string, error)
}

// vaultStore reads from HashiCorp Vault KV v2 in proxy mode: the gateway
// holds a Vault token scoped to read-only access under prefix.
type vaultStore struct {
	address string
	token   string
	mount   string
	prefix  string
	client  *http.Client
}

func newVaultStore(address, token, mount, prefix string) (*vaultStore, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid vault address %q", address)
	}
	if token == "" {
		return nil, fmt.Errorf("vault token is required")
	}
	if mount == "" {
		mount = "secret"
	}
	return &vaultStore{
		address: strings.TrimRight(address, "/"),
		token:   token,
		mount:   mount,
		prefix:  strings.Trim(prefix, "/"),
		client:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *vaultStore) Read(ctx context.Context, ref *SecretRef) (string, error) {
	path := strings.Trim(ref.Path, "/")
	if s.prefix != "" {
		path = s.prefix + "/" + path
	}
	endpoint := fmt.Sprintf("%s/v1/%s/data/%s", s.address, s.mount, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault read %s: %w", ref.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("vault read %s: %s", ref.Path, resp.Status)
	}
	var body struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("vault read %s: decoding response: %w", ref.Path, err)
	}
	value := body.Data.Data[ref.Field]
	if value == "" {
		return "", fmt.Errorf("secret %s#%s not found", ref.Path, ref.Field)
	}
	return value, nil
}
