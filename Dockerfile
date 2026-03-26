FROM rust:1.91.1-bookworm AS rust-build

WORKDIR /usr/local/src/ferriskey

COPY Cargo.toml Cargo.lock ./
COPY libs/ferriskey-cli-core/Cargo.toml ./libs/ferriskey-cli-core/
COPY libs/ferriskey-client/Cargo.toml ./libs/ferriskey-client/
COPY libs/ferriskey-commands/Cargo.toml ./libs/ferriskey-commands/



RUN \
  mkdir -p src libs/ferriskey-cli-core/src libs/ferriskey-client/src libs/ferriskey-commands/src && \
  touch libs/ferriskey-cli-core/src/lib.rs && \
  touch libs/ferriskey-client/src/lib.rs && \
  touch libs/ferriskey-commands/src/lib.rs && \
  echo "fn main() {}" > src/main.rs && \
  cargo build --release

COPY libs/ferriskey-cli-core libs/ferriskey-cli-core
COPY libs/ferriskey-client libs/ferriskey-client
COPY libs/ferriskey-commands libs/ferriskey-commands

COPY src src

RUN \

  touch libs/ferriskey-cli-core/src/lib.rs && \
  touch libs/ferriskey-client/src/lib.rs && \
  touch libs/ferriskey-commands/src/lib.rs && \
  touch src/main.rs && \
  cargo build --release

FROM debian:bookworm-slim AS cli

RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates=20230311+deb12u1 \
    libssl3=3.0.17-1~deb12u2 && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup \
    --system \
    --gid 1000 \
    ferriskey && \
    adduser \
    --system \
    --no-create-home \
    --disabled-login \
    --uid 1000 \
    --gid 1000 \
    ferriskey

USER ferriskey

FROM runtime AS api

COPY --from=rust-build /usr/local/src/ferriskey/target/release/ferriskey /usr/local/bin/

EXPOSE 80

ENTRYPOINT ["ferriskey"]
