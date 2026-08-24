// keyserver is a customer-run attested-release gateway: it releases
// secrets from the customer's own store to Tinfoil enclaves that prove a
// pinned measurement, so neither Tinfoil nor the host ever sees the values.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	log.SetFlags(0)
	listen := flag.String("listen", envDefault("LISTEN_ADDR", ":8443"), "listen address")
	tlsCert := flag.String("tls-cert", os.Getenv("TLS_CERT"), "server TLS certificate (publicly trusted; enclaves verify against system roots)")
	tlsKey := flag.String("tls-key", os.Getenv("TLS_KEY"), "server TLS key")
	policyPath := flag.String("policy", envDefault("POLICY_PATH", "policy.yaml"), "release policy file")
	backend := flag.String("backend", envDefault("BACKEND", "vault"), "secret store backend: vault or aws")
	flag.Parse()

	policy, err := LoadPolicy(*policyPath)
	if err != nil {
		log.Fatalf("keyserver: %v", err)
	}

	var store secretStore
	switch *backend {
	case "vault":
		store, err = newVaultStore(
			os.Getenv("VAULT_ADDR"),
			os.Getenv("VAULT_TOKEN"),
			envDefault("VAULT_KV_MOUNT", "secret"),
			os.Getenv("VAULT_PREFIX"),
		)
	case "aws":
		store, err = newAWSStore(context.Background(), os.Getenv("AWS_SECRETS_PREFIX"))
	default:
		log.Fatalf("keyserver: unknown backend %q (want vault or aws)", *backend)
	}
	if err != nil {
		log.Fatalf("keyserver: %v", err)
	}
	log.Printf("secret store backend: %s", *backend)

	gateway := &server{
		verifier: sdkVerifier{},
		policy:   policy,
		store:    store,
		nonces:   newNonceStore(),
	}

	if *tlsCert == "" || *tlsKey == "" {
		log.Fatal("keyserver: -tls-cert and -tls-key are required (the protocol authenticates callers via the client certificate)")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", gateway.handleChallenge)
	mux.HandleFunc("/fetch", gateway.handleFetch)
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Any client certificate is accepted at the handshake; possession
			// of the attested key is enforced per-request against REPORT_DATA.
			ClientAuth: tls.RequireAnyClientCert,
		},
	}
	log.Printf("keyserver listening on %s (policy %s)", *listen, *policyPath)
	if err := httpServer.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
		log.Fatalf("keyserver: %v", err)
	}
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
