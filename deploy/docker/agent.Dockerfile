# The agent image is intended for a privileged-enough mount of the host logs,
# not for the host network namespace.
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY apps ./apps
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/halimisoc-agent ./apps/agent

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/halimisoc-agent /halimisoc-agent
USER 65534:65534
WORKDIR /var/lib/halimisoc
ENTRYPOINT ["/halimisoc-agent"]
