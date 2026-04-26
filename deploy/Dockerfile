# syntax=docker/dockerfile:1.7

# ----- builder -------------------------------------------------------------
# Build the static musl binary. rusqlite (`bundled`) compiles libsqlite3 from
# source, so we need a C toolchain (build-base).
FROM rust:alpine AS builder

RUN apk add --no-cache build-base

WORKDIR /shade

COPY . .

RUN rustup target add x86_64-unknown-linux-musl \
 && cargo build --release --target x86_64-unknown-linux-musl --bin shade \
 && strip target/x86_64-unknown-linux-musl/release/shade

# ----- runtime -------------------------------------------------------------
# distroless/static contains only the binary, ca-certificates, /etc/passwd,
# and a `nonroot` user. No shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="shade"
LABEL org.opencontainers.image.description="Modern IRC bot and channel-management mesh, written in Rust."
LABEL org.opencontainers.image.source="https://github.com/0xdiNGo/shade"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.authors="0xdiNGo"

COPY --from=builder /shade/target/x86_64-unknown-linux-musl/release/shade /usr/local/bin/shade

USER nonroot

# 7331 mesh, 8443 admin API, 9090 metrics
EXPOSE 7331 8443 9090

VOLUME ["/var/lib/shade", "/etc/shade"]

ENTRYPOINT ["/usr/local/bin/shade"]
CMD ["run", "--config=/etc/shade/shade.toml"]
