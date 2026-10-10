# syntax=docker/dockerfile:1.7
#
# Multi-arch image for bynh-status-agent: a static musl binary on scratch.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t bynh-status-agent .
#
# Each platform is compiled natively for its own musl target (under QEMU
# emulation when it differs from the build host), so no cross toolchain is
# needed. The result is a single static binary, CA certificates and nothing
# else: no shell, no package manager, runs as UID/GID 65532.

# Pinned by digest; Dependabot keeps it current. Same toolchain as
# rust-toolchain.toml.
FROM rust:1.99.0-alpine3.22@sha256:c3a5ad77ff2e5ec99fffaf62cb518e61a9dcbd9e1d7526d281a380db0be3bb3b AS build
RUN apk add --no-cache musl-dev ca-certificates
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked \
 && cp target/release/bynh-status-agent /bynh-status-agent \
 && /bynh-status-agent version

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.title="bynh-status-agent" \
      org.opencontainers.image.description="Uptime monitoring agent for bynh" \
      org.opencontainers.image.source="https://github.com/Dokan-E-Commerce/bynh-status-agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
# The agent ships Mozilla's roots inside the binary; the system bundle is here
# for completeness and for tools that expect it.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /bynh-status-agent /bynh-status-agent
USER 65532:65532
ENTRYPOINT ["/bynh-status-agent"]
CMD ["run"]
