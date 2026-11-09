FROM packages.maestra.io/docker-hub/library/golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /app
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_TIME=unknown
COPY go.mod go.sum ./
# Modules through nora (packages.maestra.io, 3-day hold, issues-maestra#1649): CI passes
# its token as the PRIVATE_PACKAGES_TOKEN secret; a local build keeps the default proxy.
RUN --mount=type=secret,id=PRIVATE_PACKAGES_TOKEN,env=NORA_TOKEN \
    GOPROXY="${NORA_TOKEN:+https://token:${NORA_TOKEN}@packages.maestra.io/go}" go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION} -X main.buildTime=${BUILD_TIME}" -o /loki-vl-proxy ./cmd/proxy && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /healthcheck ./cmd/healthcheck

FROM packages.maestra.io/gcr/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=builder /loki-vl-proxy /usr/local/bin/loki-vl-proxy
COPY --from=builder /healthcheck /usr/local/bin/healthcheck
USER nonroot
EXPOSE 3100
ENTRYPOINT ["/usr/local/bin/loki-vl-proxy"]
