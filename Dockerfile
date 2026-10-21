# syntax=docker/dockerfile:1

# Go 1.27.3 is required: crypto/x509 rejects the compromised eMudhra
# intermediate CA keys (CVE-2026-111943). Builder and runtime images are
# digest-pinned so the toolchain and shipped trust store are fixed and
# reviewable; refresh both digests together when bumping.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /keyserver .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /keyserver /keyserver
ENTRYPOINT ["/keyserver"]
