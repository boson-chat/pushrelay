# boson pushrelay: static Go binary on distroless (non-root). The build
# stage runs on the build host's platform (no QEMU); Go cross-compiles for
# the target, so `docker buildx --platform linux/amd64,linux/arm64` is cheap.
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/pushrelay ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/pushrelay /app/pushrelay

ARG VERSION=dev
ENV PUSHRELAY_VERSION=$VERSION PUSHRELAY_ENV=production

# 8080: public API (behind the reverse proxy). 3001: /metrics, /healthz,
# /readyz, operator API (never publish).
EXPOSE 8080 3001
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/app/pushrelay", "healthcheck"]
ENTRYPOINT ["/app/pushrelay"]
CMD ["serve"]
