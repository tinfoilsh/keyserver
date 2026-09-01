package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Documents embed all verification collateral, so requests run to megabytes.
const maxRequestBytes = 8 << 20

// fetchRequest is the wire format the cvmimage boot client sends to /fetch.
// Repo selects which trusted signing identity to verify against; it grants
// nothing by itself — a document that does not authenticate as a release of
// that repo is rejected.
type fetchRequest struct {
	Repo       string          `json:"repo"`
	SecretRefs []string        `json:"secret_refs"`
	Nonce      string          `json:"nonce"`
	Document   json.RawMessage `json:"document"`
}

type server struct {
	verifier documentVerifier
	policy   *Policy
	store    secretStore
	nonces   *nonceStore
	// roots overrides the system roots for domain-pin verification (tests).
	roots *x509.CertPool
}

// handleFetch releases secrets to a caller that proves, in one connection:
// a fresh, vendor-rooted attestation of a pinned release, and possession of
// the TLS key endorsed inside it. The response travels only over the
// mutually authenticated channel keyed by that possession.
func (s *server) handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	var req fetchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		s.deny(w, r, "", http.StatusBadRequest, fmt.Errorf("decoding request: %w", err))
		return
	}

	// Consume the nonce before anything expensive: replays and unsolicited
	// documents fail here, and a failed request burns its challenge.
	nonce, err := s.nonces.Consume(req.Nonce)
	if err != nil {
		s.deny(w, r, req.Repo, http.StatusForbidden, err)
		return
	}
	if !s.policy.TrustsRepo(req.Repo) {
		s.deny(w, r, req.Repo, http.StatusForbidden, fmt.Errorf("repository is not pinned by any workload"))
		return
	}
	proof, err := s.verifier.Verify(req.Document, nonce, req.Repo)
	if err != nil {
		s.deny(w, r, req.Repo, http.StatusForbidden, err)
		return
	}
	name, workload := s.policy.Match(req.Repo, proof.Tag)
	if workload == nil {
		s.deny(w, r, req.Repo, http.StatusForbidden,
			fmt.Errorf("release %s@%s is not pinned by any workload", req.Repo, proof.Tag))
		return
	}
	if err := verifyKeyBinding(r.TLS.PeerCertificates[0], proof.TLSKeyFP); err != nil {
		s.deny(w, r, req.Repo, http.StatusForbidden, err)
		return
	}
	if err := verifyPeerDomain(r.TLS, workload.Domain, s.roots); err != nil {
		s.deny(w, r, req.Repo, http.StatusForbidden,
			fmt.Errorf("caller certificate not valid for pinned domain %q: %w", workload.Domain, err))
		return
	}
	release, err := workload.Authorize(name, req.SecretRefs)
	if err != nil {
		s.deny(w, r, req.Repo, http.StatusForbidden, err)
		return
	}

	secrets := make(map[string]string, len(release))
	for refName, ref := range release {
		value, err := s.store.Read(r.Context(), ref)
		if err != nil {
			s.deny(w, r, req.Repo, http.StatusBadGateway, fmt.Errorf("reading %q: %w", refName, err))
			return
		}
		secrets[refName] = value
	}

	log.Printf("release workload=%s release=%s@%s secrets=%v remote=%s",
		name, req.Repo, proof.Tag, req.SecretRefs, r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(secrets)
}

// verifyKeyBinding checks that the connection's client TLS key is the one
// the attested enclave endorsed in its document. This is what makes a
// captured or relayed attestation useless — the response only flows over a
// channel keyed by the endorsed private key, which never leaves enclave
// memory.
func verifyKeyBinding(cert *x509.Certificate, attestedFP string) error {
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("encoding client public key: %w", err)
	}
	fingerprint := sha256.Sum256(spki)
	presented := hex.EncodeToString(fingerprint[:])
	if subtle.ConstantTimeCompare([]byte(presented), []byte(strings.ToLower(attestedFP))) != 1 {
		return fmt.Errorf("client TLS key does not match the attested key")
	}
	return nil
}

// verifyPeerDomain requires the caller's certificate chain to be CA-issued
// for the pinned domain. Combined with the key binding, this stops a second
// deployment of the same public repo — identical attested build, different
// operator — from receiving this workload's secrets: they cannot obtain a
// trusted certificate for a domain they do not control.
func verifyPeerDomain(state *tls.ConnectionState, domain string, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       domain,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func (s *server) deny(w http.ResponseWriter, r *http.Request, repo string, status int, err error) {
	log.Printf("deny repo=%q remote=%s: %v", repo, r.RemoteAddr, err)
	http.Error(w, err.Error(), status)
}
