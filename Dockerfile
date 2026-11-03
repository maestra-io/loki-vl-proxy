FROM golang:1.27.3-alpine3.24 AS builder
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

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /loki-vl-proxy /usr/local/bin/loki-vl-proxy
COPY --from=builder /healthcheck /usr/local/bin/healthcheck
USER nonroot
EXPOSE 3100
ENTRYPOINT ["/usr/local/bin/loki-vl-proxy"]
