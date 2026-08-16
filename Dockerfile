# =============================================================================
# Dockerfile — CDX Full Node (Codex Coin)
# Base: Ubuntu 22.04 (jammy)
#
# Cara pakai:
#   docker build -t cdx-node .
#   docker run -d --name cdx-main -p 19333:19333 \
#     -v cdx-data:/cdx/data \
#     -e CDX_NETWORK=mainnet \
#     -e CDX_RPCUSER=cdx -e CDX_RPCPASSWORD=cdx \
#     cdx-node
#
# RPC hanya bind ke 127.0.0.1 di dalam container (default node).
# Untuk akses RPC dari host: jalankan dengan --network host, atau
# expose via port-forwarding tambahan (mis. socat).
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Salin source project (dockerignore mengecualikan build/, .git, dll)
COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)" \
    && cmake --install build --prefix /opt/cdx 2>/dev/null || true

# cmake --install tidak terdefinisi di CMakeLists ini; salin binary manual
RUN mkdir -p /opt/cdx/bin \
    && cp build/cdxd /opt/cdx/bin/ \
    && cp build/cdx-cli /opt/cdx/bin/ \
    && cp build/cdx-genesis /opt/cdx/bin/

# ---------------------------------------------------------------------------
# Stage 2: runtime (image kecil)
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Runtime deps: libssl (untuk crypto) + util untuk healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /cdx cdxuser

COPY --from=builder /opt/cdx/bin/ /usr/local/bin/

# Data dir node
VOLUME ["/cdx/data"]
WORKDIR /cdx

# Port P2P: mainnet 19333, testnet 19334, regtest 19444
EXPOSE 19333 19334 19444
# Port RPC (localhost saja di dalam container; tidak di-publish otomatis)
EXPOSE 19343 19344 19445

# Entrypoint: jalankan node sesuai env
# (entrypoint berjalan sebagai root utk chown data dir, lalu drop privilege
#  ke cdxuser sebelum menjalankan cdxd)
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["cdxd"]
