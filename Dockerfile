# The latest stable Rust, on Debian 12 (bookworm) like the image the binary runs in.
FROM rust:bookworm AS builder

ARG GO_VERSION=1.22.12

RUN apt-get update && \
    apt-get install -y \
    clang \
    cmake \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /usr/src/app

COPY scripts/build-pt.sh ./pt-build.sh
COPY scripts/build-psiphon.sh ./psiphon-build.sh
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN bash ./pt-build.sh linux "$(dpkg --print-architecture)" /usr/src/app/pt
RUN bash ./psiphon-build.sh linux "$(dpkg --print-architecture)" /usr/src/app/pt

RUN cargo build --release --locked --features tor

FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/aether /usr/local/bin/aether
COPY --from=builder /usr/src/app/pt /usr/local/bin/pt

VOLUME ["/data"]

EXPOSE 1819

# the flags the image needs, with any of your own appended after them
ENTRYPOINT ["aether", "--bind", "0.0.0.0:1819", "--config", "/data/aether.toml"]
CMD []
