# Multi-stage build: the final image contains one static binary and no toolchain.
FROM golang:1.26-alpine AS build

WORKDIR /src

# Copy manifests first so dependency download is cached independently of source.
COPY go.mod go.sum ./
RUN go mod download

COPY apps ./apps
COPY internal ./internal
COPY packages ./packages

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/halimisoc-api ./apps/api

FROM scratch

# Certificates are needed for outbound TLS (AI provider, future integrations).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/halimisoc-api /halimisoc-api
# Detection rules are compiled into the image as a fallback; the deployment
# mounts an updated directory over this path.
COPY --from=build /src/packages/rules /etc/halimisoc/rules

# Run as an unprivileged user. A numeric UID is required for scratch images.
USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/halimisoc-api"]
