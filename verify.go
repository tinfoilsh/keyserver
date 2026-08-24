package main

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// verified is what document verification proves: the build identity
// (authenticated against the trusted repo's Sigstore signing identity, never
// the document's own claims) and the TLS key the enclave endorsed for
// channel binding.
type verified struct {
	Tag      string
	Digest   string
	TLSKeyFP string
}

// documentVerifier authenticates a v3 attestation document that was built
// against the server-issued nonce, trusting only releases of repo.
type documentVerifier interface {
	Verify(document, nonce []byte, repo string) (*verified, error)
}

// sdkVerifier delegates to the Tinfoil SDK's v3 verification: envelope and
// REPORT_DATA recomputation against the nonce, Sigstore code/platform/
// freshness authentication, and the CPU quote chained to the AMD/Intel
// roots with debug rejected. All collateral travels inside the document, so
// verification is offline.
type sdkVerifier struct{}

func (sdkVerifier) Verify(document, nonce []byte, repo string) (*verified, error) {
	doc, err := client.VerifyDocumentV3(document, nonce, repo)
	if err != nil {
		return nil, err
	}
	tlsKeyFP, err := doc.TLSPublicKeyFP()
	if err != nil {
		return nil, fmt.Errorf("document endorses no TLS key: %w", err)
	}
	if doc.CodeTag == "" {
		return nil, fmt.Errorf("document carries no authenticated release tag")
	}
	return &verified{
		Tag:      doc.CodeTag,
		Digest:   doc.CodeDigest,
		TLSKeyFP: tlsKeyFP,
	}, nil
}
