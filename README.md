# Tinfoil Keyserver

Run your own keyserver and your Tinfoil Containers get secrets that Tinfoil
never sees. The keyserver sits in front of your secret store (HashiCorp Vault
or AWS Secrets Manager) and releases a secret only to an enclave that proves —
with fresh hardware attestation — that it is running the exact release you
pinned. Released values travel only into enclave memory and are never
persisted.

## Quickstart

### 1. Run the keyserver

Needs a publicly trusted TLS certificate on a real domain (enclaves verify it
against system roots) and your policy. Attestation verification is fully
offline — the only network the keyserver needs is to your secret store:

```bash
docker run -p 8443:8443 \
  -v $PWD/policy.yaml:/policy.yaml -v $PWD/tls:/tls \
  -e BACKEND=vault -e VAULT_ADDR=... -e VAULT_TOKEN=... -e VAULT_PREFIX=tinfoil \
  ghcr.io/tinfoilsh/keyserver -policy /policy.yaml -tls-cert /tls/cert.pem -tls-key /tls/key.pem
```

### 2. Write your policy

`policy.yaml` pins which build may receive which secrets: your workload repo
and a release tag. The enclave's attestation document is authenticated
against that repo's Sigstore signing identity — the same verification
Tinfoil SDK clients do — and its release tag must equal the pin. Bump the tag
to authorize a new release. See `policy.example.yaml`.

```yaml
workloads:
  hello-world:
    repo: org/hello-world
    tag: v1.0.0
    domain: hello-world.example.com  # your deployment's domain (recommended)
    secrets:
      DEMO_SECRET: {path: workloads/hello-world/demo, field: value}
```

Launch with `debug: false` — debug-enabled enclaves are rejected.

### 3. Store the secret

**HashiCorp Vault** (`BACKEND=vault`) — reads KV v2 at
`VAULT_KV_MOUNT/VAULT_PREFIX/<path>`, key `<field>`, with a read-only token:

```bash
vault policy write tinfoil-keyserver - <<'EOF'
path "secret/data/tinfoil/*" { capabilities = ["read"] }
EOF
vault token create -policy=tinfoil-keyserver -period=768h
vault kv put -mount=secret tinfoil/workloads/hello-world/demo value=hunter2
```

**AWS Secrets Manager** (`BACKEND=aws`) — `<path>` is the secret name under
`AWS_SECRETS_PREFIX`, `<field>` a key in its JSON value. Credentials via the
usual chain (IAM role, env keys, or profile) plus `AWS_REGION`:

```bash
aws secretsmanager create-secret \
  --name tinfoil/workloads/hello-world/demo \
  --secret-string '{"value": "hunter2"}'
```

Grant the keyserver only `secretsmanager:GetSecretValue` on
`arn:aws:secretsmanager:<region>:<account>:secret:tinfoil/*`.

### 4. Wire your deployment

In your measured `tinfoil-config.yml`:

```yaml
vault-url: https://keys.example.com
containers:
  - name: app
    image: ghcr.io/org/app@sha256:...
    secrets: [DEMO_SECRET]
```

At boot the enclave fetches `DEMO_SECRET` and injects it as an env var —
fail-closed, so it never starts with the variable missing. Enclaves fetch at
every boot; keep the keyserver reachable, serve `/challenge` and `/fetch`
directly at `vault-url` (the enclave refuses redirects).

## How release is decided

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/protocol-dark.svg">
  <img src="docs/protocol.svg" alt="Sequence diagram: the enclave requests a single-use nonce from the keyserver's /challenge endpoint, builds a fresh v3 attestation document over it, and POSTs /fetch over mutual TLS; the keyserver checks the nonce, verifies the document offline (quote to AMD/Intel roots, Sigstore-authenticated release of the pinned repo, debug rejected), requires the authenticated tag to equal the pin, the caller's TLS key to equal the endorsed key, and the caller's certificate to be CA-issued for the pinned domain, then reads the approved secrets from the customer store and returns them over the key-bound channel." width="820">
</picture>

Every request must pass all of these, or nothing is released:

- The nonce was issued by this keyserver, is unexpired, and is used once —
  the attestation document is provably fresh.
- The document verifies **offline** via the [Tinfoil SDK](https://github.com/tinfoilsh/tinfoil-go):
  the quote chains to the AMD/Intel roots (debug rejected), and the embedded
  Sigstore artifacts authenticate it as a release of the pinned repo — the
  authenticated tag must equal the pinned tag.
- The caller's TLS key matches the key endorsed inside the document, so a
  captured or relayed attestation is useless.
- With a pinned `domain`, the caller's certificate must be CA-issued for it —
  someone else deploying the same public repo cannot qualify.

## Development

`go test ./...` exercises the full request path — the challenge flow,
mutual-TLS key binding, release pinning, domain pinning, all-or-nothing
release — with stub evidence, no hardware required. Testing against a live
enclave requires a workload repo with an attested release, since a v3
document cannot be built without one.
