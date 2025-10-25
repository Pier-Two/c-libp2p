########## Base Stage ##########
# Accept architecture from buildx and pick the matching base image
ARG TARGETARCH
ARG GO_VERSION=1.23.8
FROM --platform=linux/${TARGETARCH:-amd64} ubuntu:22.04 AS base

ARG TARGETARCH
ARG GO_VERSION

# Install build tools, runtime dependencies, Redis, Rust toolchain, and helpers such as curl/wget/unzip
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
        cargo \
        cmake \
        git \
        libssl-dev \
        libssl3 \
        pkg-config \
        redis-server \
        redis-tools \
        rustc \
        unzip \
        wget \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Go toolchain that matches the transport interop test requirements
RUN ARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "${ARCH}" in \
        amd64|x86_64) GO_ARCH=amd64 ;; \
        arm64|aarch64) GO_ARCH=arm64 ;; \
        *) echo "Unsupported architecture: ${ARCH}" >&2 ; exit 1 ;; \
    esac && \
    wget -q "https://dl.google.com/go/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tgz && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm /tmp/go.tgz

# Ensure Go binaries are discoverable for every shell
ENV PATH=/usr/local/go/bin:${PATH}

########## Builder Stage ##########
FROM base AS builder

# Set working directory and copy the project sources
WORKDIR /src
COPY . /src/c-libp2p

# Build the interop binary once during image build
RUN cd c-libp2p && \
    rm -rf build && mkdir build && cd build && \
    cmake .. && \
    make -j"$(nproc)" interop-c && \
    strip interop-c

########## Runtime Stage ##########
FROM base

# Copy the interop binary from builder
COPY --from=builder /src/c-libp2p/build/interop-c /usr/local/bin/interop-c

# Copy all shared libraries from builder - both .so and versioned libraries
COPY --from=builder /src/c-libp2p/build/lib/ /usr/local/lib/

# Set library search path
ENV LD_LIBRARY_PATH=/usr/local/lib

# Update library cache
RUN ldconfig

# Entrypoint: run the interop binary by default (tests can override this)
ENTRYPOINT ["/usr/local/bin/interop-c"]
