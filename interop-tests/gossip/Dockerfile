########## Base Stage ##########
# Build image that includes Shadow and gossip interop binaries
ARG TARGETARCH=amd64
ARG GO_VERSION=1.23.8
FROM --platform=linux/${TARGETARCH} ubuntu:22.04 AS base

ARG TARGETARCH
ARG GO_VERSION

# Install build tools, runtime dependencies, Redis, Rust toolchain, and helpers such as curl/wget/unzip
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        findutils \
        flex \
        git \
        graphviz \
        libclang-dev \
        libglib2.0-0 \
        libglib2.0-dev \
        libgraphviz-dev \
        libigraph-dev \
        libssl-dev \
        libssl3 \
        netbase \
        ninja-build \
        pkg-config \
        python3 \
        python3-networkx \
        python3-pip \
        python3-venv \
        redis-server \
        redis-tools \
        unzip \
        util-linux \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Go toolchain required by the interop build
RUN ARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "${ARCH}" in \
        amd64|x86_64) GO_ARCH=amd64 ;; \
        arm64|aarch64) GO_ARCH=arm64 ;; \
        *) echo "Unsupported architecture: ${ARCH}" >&2 ; exit 1 ;; \
    esac && \
    wget -q "https://dl.google.com/go/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tgz && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm /tmp/go.tgz

# Ensure Go and Rust binaries are discoverable for every shell
ENV RUSTUP_HOME=/root/.rustup
ENV CARGO_HOME=/root/.cargo
ENV PATH=/usr/local/go/bin:${PATH}

# Install rustup with a modern Rust toolchain for Shadow
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.83.0 && \
    /root/.cargo/bin/rustup component add rustfmt clippy && \
    /root/.cargo/bin/rustup toolchain install nightly

# Ensure both Go and Rust toolchains are in PATH for all subsequent layers
ENV PATH=/root/.cargo/bin:/usr/local/go/bin:${PATH}

########## Shadow Builder Stage ##########
FROM base AS shadow-builder

ARG TARGETARCH
ENV RUSTUP_TOOLCHAIN=nightly

RUN if [ "${TARGETARCH}" != "amd64" ]; then \
        echo "Shadow build currently requires linux/amd64 (got ${TARGETARCH})." >&2; \
        exit 1; \
    fi

# Ensure /bin/sh resolves to bash to avoid dash/qemu incompatibilities
RUN ln -sf /bin/bash /bin/sh

WORKDIR /tmp/shadow
RUN git clone --depth 1 https://github.com/shadow/shadow.git .

# Build and install Shadow into a relocatable prefix
RUN ./setup build --clean && \
    mkdir -p /opt/shadow && \
    ./setup install --prefix /opt/shadow && \
    rm -rf /tmp/shadow

########## Builder Stage ##########
FROM shadow-builder AS builder

# Set working directory and copy the project sources
WORKDIR /src
COPY . /src/c-libp2p

# Build the interop binaries once during image build
RUN cd c-libp2p && \
    rm -rf build && mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .. && \
    cmake --build . --target interop-c --target gossipsub-interop --parallel && \
    strip interop-c gossipsub-interop

########## Runtime Stage ##########
FROM base

# Copy the gossipsub interop binary from builder
COPY --from=builder /src/c-libp2p/build/gossipsub-interop /usr/local/bin/gossipsub-interop

# Copy all shared libraries from builder - both .so and versioned libraries
COPY --from=builder /src/c-libp2p/build/lib/ /usr/local/lib/

# Copy the Shadow installation from the shadow builder stage
COPY --from=shadow-builder /opt/shadow /opt/shadow

# Set library search path
ENV LD_LIBRARY_PATH=/usr/local/lib

# Ensure Shadow and toolchains are available in PATH
ENV PATH=/opt/shadow/bin:/root/.cargo/bin:/usr/local/go/bin:${PATH}

# Update library cache
RUN ldconfig

# Default to bash for interactive/test usage
ENTRYPOINT ["/bin/bash"]
