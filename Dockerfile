ARG GO_VERSION=1.27.0

FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY . .

RUN go mod download
# VERSION is supplied by ci.yml (build-args) and reaches the binary through -X.
# Without both halves the pipeline computes a version that is thrown away and
# every log line reports the dev default instead of the build that is running.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/server ./cmd/server
RUN mkdir -p /out/data

FROM ghcr.io/wntrtech/scratch:v1.0.0-3
COPY --from=build /out/server /server

# Baked LOTL signer set — the certificates authorised to sign the EU List of
# Trusted Lists. A normal deploy needs no trust configuration; for an urgent
# rotation before the next image build, mount a newer manifest and override
# LOTL_BOOTSTRAP_CERTS_PATH to it.
COPY --from=build /src/trust-config/lotl-signers.yaml /etc/trust-anchor/lotl-signers.yaml
ENV LOTL_BOOTSTRAP_CERTS_PATH=/etc/trust-anchor/lotl-signers.yaml

# The filesystem snapshot store is opt-in (TRUST_SNAPSHOT_DIR); its conventional location is
# /var/lib/trust-anchor. The directory ships in the image owned by the unprivileged user the
# service runs as, so a fresh named volume mounted there inherits that ownership and the first
# start succeeds without a --user flag or a chown step. Deliberately no VOLUME instruction: it
# would create an anonymous volume on every run, including the S3 and Postgres deployments that
# never touch the directory.
COPY --from=build --chown=1000:1000 /out/data /var/lib/trust-anchor

EXPOSE 8080/tcp
ENTRYPOINT ["/server", "web"]
HEALTHCHECK --start-period=20s --start-interval=5s --interval=1m --timeout=10s --retries=5 \
    CMD ["/server", "health"]
