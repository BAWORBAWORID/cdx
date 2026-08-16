#!/usr/bin/env bash
# =============================================================================
# docker-entrypoint.sh — jalankan CDX full node di dalam container.
#
# Variabel environment yang didukung:
#   CDX_NETWORK        mainnet|testnet|regtest   (default: mainnet)
#   CDX_DATADIR        lokasi data               (default: /data — Railway Volumes)
#   CDX_RPCUSER        user RPC                  (default: cdx)
#   CDX_RPCPASSWORD    password RPC              (default: cdx)
#   CDX_PORT           port P2P (override; Railway inject env PORT otomatis)
#   CDX_RPCPORT        port RPC (override; default sesuai network: 19343 dll)
#   CDX_MINER_ADDRESS  alamat payout mining      (kosong = mining nonaktif)
#   CDX_GENERATE       "1" untuk mining terus-menerus (regtest/dev)
#   CDX_EXTRA_ARGS     argumen tambahan untuk cdxd
# =============================================================================
set -euo pipefail

NETWORK="${CDX_NETWORK:-mainnet}"
DATADIR="${CDX_DATADIR:-/data}"
RPCUSER="${CDX_RPCUSER:-cdx}"
RPCPASSWORD="${CDX_RPCPASSWORD:-cdx}"

ARGS=(
    "-network=${NETWORK}"
    "-datadir=${DATADIR}"
    "-rpcuser=${RPCUSER}"
    "-rpcpassword=${RPCPASSWORD}"
)

# Railway: inject env PORT (port TCP yang di-expose platform) ke P2P node
PORT="${CDX_PORT:-${PORT:-}}"
if [[ -n "${PORT}" ]]; then
    ARGS+=("-port=${PORT}")
fi

# Override port RPC (hindari konflik bila PORT == default RPC port)
if [[ -n "${CDX_RPCPORT:-}" ]]; then
    ARGS+=("-rpcport=${CDX_RPCPORT}")
fi

# Mining: aktif bila alamat diberikan (atau generate mode)
if [[ -n "${CDX_MINER_ADDRESS:-}" ]]; then
    ARGS+=("-miningaddress=${CDX_MINER_ADDRESS}")
fi
if [[ "${CDX_GENERATE:-0}" == "1" ]]; then
    ARGS+=("-generate")
fi
if [[ -n "${CDX_EXTRA_ARGS:-}" ]]; then
    # pecah string menjadi argumen terpisah
    read -r -a EXTRA <<< "${CDX_EXTRA_ARGS}"
    ARGS+=("${EXTRA[@]}")
fi

# Data dir (volume Docker dibuat root) — beri kepemilikan ke cdxuser
mkdir -p "${DATADIR}"
chown -R cdxuser:cdxuser /cdx "${DATADIR}"

echo "[cdx] starting ${NETWORK} node (data: ${DATADIR})"
# drop privilege ke cdxuser lalu jalankan node
exec su -s /bin/bash cdxuser -c "exec cdxd $(printf '%q ' "${ARGS[@]}")"
