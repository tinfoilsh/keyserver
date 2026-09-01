package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubVerifier stands in for the SDK's v3 verification, enforcing the same
// contract: the document must carry the server-issued nonce and authenticate
// as a release of the trusted repo. Handler tests exercise the real mTLS
// binding, nonce, and policy paths without hardware evidence.
type stubVerifier struct{}

type stubDocument struct {
	Repo     string `json:"repo"`
	Tag      string `json:"tag"`
	Nonce    string `json:"nonce"`
	TLSKeyFP string `json:"tls_key_fp"`
}

func (stubVerifier) Verify(document, nonce []byte, repo string) (*verified, error) {
	var doc stubDocument
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("stub: %w", err)
	}
	if doc.Nonce != hex.EncodeToString(nonce) {
		return nil, fmt.Errorf("stub: document nonce mismatch")
	}
	if doc.Repo != repo {
		return nil, fmt.Errorf("stub: document does not authenticate as a release of %s", repo)
	}
	return &verified{Tag: doc.Tag, TLSKeyFP: doc.TLSKeyFP}, nil
}

// mapStore is an in-memory secretStore for tests: {path: {field: value}}.
type mapStore map[string]map[string]string

func (s mapStore) Read(_ context.Context, ref *SecretRef) (string, error) {
	value := s[ref.Path][ref.Field]
	if value == "" {
		return "", fmt.Errorf("secret %s#%s not found", ref.Path, ref.Field)
	}
	return value, nil
}

// enclaveIdentity mimics a booted enclave: a TLS keypair whose SPKI
// fingerprint the attestation document endorses.
type enclaveIdentity struct {
	cert  tls.Certificate
	keyFP string
}

func newIdentity(t *testing.T, template *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *enclaveIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(spki)
	return &enclaveIdentity{
		cert:  tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		keyFP: hex.EncodeToString(fingerprint[:]),
	}
}

// testCA stands in for the public CA that issues a deployment's certificate
// for its domain; the gateway under test trusts it as its only root.
type testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

var (
	caOnce sync.Once
	ca     *testCA
	caErr  error
)

func trustedCA(t *testing.T) *testCA {
	t.Helper()
	caOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			caErr = err
			return
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "test-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			caErr = err
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			caErr = err
			return
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		ca = &testCA{cert: cert, key: key, roots: roots}
	})
	if caErr != nil {
		t.Fatal(caErr)
	}
	return ca
}

const testDomain = "hello.test"

// issuedIdentity is an enclave whose certificate the trusted CA issued for
// domain, as a real deployment's public certificate is.
func issuedIdentity(t *testing.T, domain string) *enclaveIdentity {
	ca := trustedCA(t)
	return newIdentity(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, ca.cert, ca.key)
}

// newEnclaveIdentity mimics the pinned deployment itself.
func newEnclaveIdentity(t *testing.T) *enclaveIdentity {
	return issuedIdentity(t, testDomain)
}

func newSelfSignedIdentity(t *testing.T) *enclaveIdentity {
	return newIdentity(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "enclave-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, nil, nil)
}

func (e *enclaveIdentity) document(t *testing.T, repo, tag, nonce string) json.RawMessage {
	t.Helper()
	doc, err := json.Marshal(stubDocument{Repo: repo, Tag: tag, Nonce: nonce, TLSKeyFP: e.keyFP})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func testPolicy() *Policy {
	return &Policy{Workloads: map[string]*Workload{
		"hello": {
			Repo:   "org/hello",
			Tag:    "v1.0.0",
			Domain: testDomain,
			Secrets: map[string]*SecretRef{
				"DEMO_SECRET": {Path: "hello/demo", Field: "value"},
				"MISSING":     {Path: "hello/missing", Field: "value"},
			},
		},
	}}
}

func startGatewayWith(t *testing.T, gateway *server) *httptest.Server {
	t.Helper()
	if gateway.nonces == nil {
		gateway.nonces = newNonceStore()
	}
	if gateway.roots == nil {
		gateway.roots = trustedCA(t).roots
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", gateway.handleChallenge)
	mux.HandleFunc("/fetch", gateway.handleFetch)
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func startGateway(t *testing.T) *httptest.Server {
	return startGatewayWith(t, &server{
		verifier: stubVerifier{},
		policy:   testPolicy(),
		store:    mapStore{"hello/demo": {"value": "hunter2"}},
	})
}

func clientAs(ts *httptest.Server, id *enclaveIdentity) *http.Client {
	client := ts.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{id.cert}
	return client
}

func challengeAs(t *testing.T, ts *httptest.Server, id *enclaveIdentity) string {
	t.Helper()
	resp, err := clientAs(ts, id).Post(ts.URL+"/challenge", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status = %d", resp.StatusCode)
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	return challenge.Nonce
}

func fetchAs(t *testing.T, ts *httptest.Server, id *enclaveIdentity, req fetchRequest) (*http.Response, map[string]string) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := clientAs(ts, id).Post(ts.URL+"/fetch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	var secrets map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		t.Fatal(err)
	}
	return resp, secrets
}

func TestChallengeAndFetchReleases(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, id)
	resp, secrets := fetchAs(t, ts, id, fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET"},
		Nonce:      nonce,
		Document:   id.document(t, "org/hello", "v1.0.0", nonce),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if secrets["DEMO_SECRET"] != "hunter2" {
		t.Fatalf("secrets = %v", secrets)
	}
}

func TestFetchRejectsNonceReplay(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, id)
	request := fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET"},
		Nonce:      nonce,
		Document:   id.document(t, "org/hello", "v1.0.0", nonce),
	}
	if resp, _ := fetchAs(t, ts, id, request); resp.StatusCode != http.StatusOK {
		t.Fatalf("first fetch status = %d", resp.StatusCode)
	}
	if resp, _ := fetchAs(t, ts, id, request); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed fetch status = %d, want 403", resp.StatusCode)
	}
}

func TestFetchRejectsUnissuedNonce(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := hex.EncodeToString(bytes.Repeat([]byte{7}, 32))
	resp, _ := fetchAs(t, ts, id, fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET"},
		Nonce:      nonce,
		Document:   id.document(t, "org/hello", "v1.0.0", nonce),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestFetchRejectsUntrustedRepo(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, id)
	resp, _ := fetchAs(t, ts, id, fetchRequest{
		Repo:       "org/other",
		SecretRefs: []string{"DEMO_SECRET"},
		Nonce:      nonce,
		Document:   id.document(t, "org/other", "v1.0.0", nonce),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestFetchRejectsUnpinnedTag(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, id)
	// A genuine, authenticated release of the trusted repo — but not the tag
	// the policy pins.
	resp, _ := fetchAs(t, ts, id, fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET"},
		Nonce:      nonce,
		Document:   id.document(t, "org/hello", "v0.9.0", nonce),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestFetchRejectsUnattestedKey(t *testing.T) {
	ts := startGateway(t)
	attested := newEnclaveIdentity(t)
	interloper := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, interloper)
	// The interloper relays a genuine document endorsing the attested
	// enclave's key but holds a different TLS key — binding must reject it.
	resp, _ := fetchAs(t, ts, interloper, fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET"},
		Nonce:      nonce,
		Document:   attested.document(t, "org/hello", "v1.0.0", nonce),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestFetchRejectsUnauthorizedRef(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, id)
	resp, _ := fetchAs(t, ts, id, fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET", "OTHER"},
		Nonce:      nonce,
		Document:   id.document(t, "org/hello", "v1.0.0", nonce),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestFetchAllOrNothingOnStoreMiss(t *testing.T) {
	ts := startGateway(t)
	id := newEnclaveIdentity(t)
	nonce := challengeAs(t, ts, id)
	resp, _ := fetchAs(t, ts, id, fetchRequest{
		Repo:       "org/hello",
		SecretRefs: []string{"DEMO_SECRET", "MISSING"},
		Nonce:      nonce,
		Document:   id.document(t, "org/hello", "v1.0.0", nonce),
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("release succeeded with an unreadable secret")
	}
}

func TestFetchDomainPin(t *testing.T) {
	ts := startGateway(t)

	request := func(id *enclaveIdentity) int {
		nonce := challengeAs(t, ts, id)
		resp, _ := fetchAs(t, ts, id, fetchRequest{
			Repo:       "org/hello",
			SecretRefs: []string{"DEMO_SECRET"},
			Nonce:      nonce,
			Document:   id.document(t, "org/hello", "v1.0.0", nonce),
		})
		return resp.StatusCode
	}

	if status := request(issuedIdentity(t, testDomain)); status != http.StatusOK {
		t.Fatalf("CA-issued cert for pinned domain: status = %d", status)
	}
	if status := request(issuedIdentity(t, "other.test")); status != http.StatusForbidden {
		t.Fatalf("CA-issued cert for wrong domain: status = %d, want 403", status)
	}
	if status := request(newSelfSignedIdentity(t)); status != http.StatusForbidden {
		t.Fatalf("self-signed cert: status = %d, want 403", status)
	}
}
