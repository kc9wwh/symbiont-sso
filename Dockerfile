# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27.2-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/symbiont ./cmd/symbiont

# ---- runtime ----------------------------------------------------------------
# distroless/static: no shell, no package manager, CA certificates and tzdata
# included. :nonroot runs as uid/gid 65532.
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="symbiont" \
      org.opencontainers.image.description="SAML IdP bridge to an upstream OpenID Connect provider" \
      org.opencontainers.image.source="https://github.com/kc9wwh/symbiont-sso" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/symbiont /usr/local/bin/symbiont

USER 65532:65532
ENV SYMBIONT_LISTEN_ADDR=:8080
EXPOSE 8080

# No HEALTHCHECK: the image has no shell or curl. Point your orchestrator's
# HTTP check at GET /healthz (see README).
ENTRYPOINT ["/usr/local/bin/symbiont"]
CMD ["serve"]
