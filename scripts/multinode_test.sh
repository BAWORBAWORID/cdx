#!/usr/bin/env bash
# =============================================================================
# CDX multi-node live test
#   Node A (regtest, mining)  <-- Node B, Node C (sync + relay)
#
# Menguji: P2P handshake, chain sync, transaction relay, mining, UTXO,
# dan kesepakatan konsensus (height/tip/chainwork identik di semua node).
#
# Catatan: seluruh test dijalankan dalam SATU shell — node background di-kill
# ketika shell keluar, jadi jangan pecah jadi beberapa perintah.
# =============================================================================
set -u
cd "$(dirname "$0")/.."

BIN=./build/cdxd
A_DATA=/tmp/cdx-node-a; B_DATA=/tmp/cdx-node-b; C_DATA=/tmp/cdx-node-c
A_PORT=19444; A_RPC=19445
B_PORT=19446; B_RPC=19447
C_PORT=19448; C_RPC=19449
USERPASS="cdx:cdx"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  [PASS] $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

cleanup() { pkill -9 -x cdxd 2>/dev/null; }
trap cleanup EXIT

rpc() { # rpc <rpcport> <method> <jsonparams>
    curl -s -m 5 -u "$USERPASS" -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" \
        "http://127.0.0.1:$1/"
}

rpc_result() { # ekstrak .result dari JSON
    python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d.get('result')) if 'result' in d else '')"
}

echo "== 1. mulai node A (mining), B, C =="
pkill -9 -x cdxd 2>/dev/null; sleep 1
rm -rf "$A_DATA" "$B_DATA" "$C_DATA"
stdbuf -oL $BIN -network=regtest -datadir=$A_DATA -port=$A_PORT -rpcport=$A_RPC -mining > /tmp/mn-a.log 2>&1 &
stdbuf -oL $BIN -network=regtest -datadir=$B_DATA -port=$B_PORT -rpcport=$B_RPC -connect=127.0.0.1:$A_PORT > /tmp/mn-b.log 2>&1 &
stdbuf -oL $BIN -network=regtest -datadir=$C_DATA -port=$C_PORT -rpcport=$C_RPC -connect=127.0.0.1:$A_PORT > /tmp/mn-c.log 2>&1 &

# tunggu RPC A aktif
for i in $(seq 1 30); do
    curl -s -m 1 -u "$USERPASS" -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:$A_RPC/ >/dev/null 2>&1 && break
    sleep 1
done

echo "== 2. mining sampai coinbase A matang (height >= 125) =="
H=0
for i in $(seq 1 120); do
    H=$(rpc $A_RPC getblockcount | rpc_result | tr -d '"')
    [ "${H:-0}" -ge 125 ] 2>/dev/null && break
    sleep 1
done
echo "   A height: $H"
[ "${H:-0}" -ge 125 ] && ok "A mining ke height >= 125 (coinbase maturity)" || bad "A tidak mencapai height 125 (H=$H)"

echo "== 3. sinkronisasi: B dan C mengejar A =="
# A masih mining; hentikan dulu agar height stabil untuk verifikasi sync penuh.
# (selama A mining terus, B/C selalu tertinggal beberapa block — itu normal)
rpc $A_RPC stopmining >/dev/null 2>&1
sleep 2
HA_STABLE=$(rpc $A_RPC getblockcount | rpc_result | tr -d '"')
HB=0; HC=0
for i in $(seq 1 90); do
    HB=$(rpc $B_RPC getblockcount | rpc_result | tr -d '"')
    HC=$(rpc $C_RPC getblockcount | rpc_result | tr -d '"')
    [ "${HB:-0}" = "$HA_STABLE" ] && [ "${HC:-0}" = "$HA_STABLE" ] 2>/dev/null && break
    sleep 1
done
echo "   B height: ${HB:-?}, C height: ${HC:-?}, A height: $HA_STABLE"
[ "${HB:-0}" = "$HA_STABLE" ] && ok "B tersinkron penuh ke height $HA_STABLE" || bad "B tidak sinkron (B=$HB A=$HA_STABLE)"
[ "${HC:-0}" = "$HA_STABLE" ] && ok "C tersinkron penuh ke height $HA_STABLE" || bad "C tidak sinkron (C=$HC A=$HA_STABLE)"

# tip hash + chainwork identik?
TA=$(rpc $A_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bestblockhash'])")
TB=$(rpc $B_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bestblockhash'])")
TC=$(rpc $C_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bestblockhash'])")
WA=$(rpc $A_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['chainwork'])")
WB=$(rpc $B_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['chainwork'])")
echo "   tip A=$TA"
echo "   tip B=$TB"
echo "   tip C=$TC"
[ "$TA" = "$TB" ] && [ "$TA" = "$TC" ] && ok "tip hash identik di semua node" || bad "tip hash berbeda"
[ "$WA" = "$WB" ] && ok "chainwork identik (A=B)" || bad "chainwork berbeda (A=$WA B=$WB)"

echo "== 4. koneksi P2P =="
NA=$(rpc $A_RPC getnetworkinfo | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin)['connections'])")
NB=$(rpc $B_RPC getnetworkinfo | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin)['connections'])")
NC=$(rpc $C_RPC getnetworkinfo | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin)['connections'])")
echo "   koneksi A=$NA B=$NB C=$NC"
[ "${NA:-0}" -ge 2 ] && ok "A terhubung ke 2 peer" || bad "A koneksi < 2 ($NA)"
[ "${NB:-0}" -ge 1 ] && ok "B terhubung ke A" || bad "B tidak terhubung ($NB)"
[ "${NC:-0}" -ge 1 ] && ok "C terhubung ke A" || bad "C tidak terhubung ($NC)"

echo "== 5. transaction relay: A -> B, C =="
# stop mining dulu agar relay teramati sebelum tx di-mine
rpc $A_RPC stopmining >/dev/null 2>&1
sleep 1
B_ADDR=$(rpc $B_RPC getnewaddress | rpc_result | tr -d '"')
echo "   B address: $B_ADDR"
TXID=$(rpc $A_RPC sendtoaddress "[\"$B_ADDR\",\"1.5\"]" | rpc_result | tr -d '"')
echo "   txid: $TXID"
[ -n "$TXID" ] && [ "$TXID" != "error" ] && ok "A membuat & mengirim transaksi (txid=$TXID)" || bad "sendtoaddress gagal (txid=$TXID)"
MSA=$(rpc $A_RPC getmempoolinfo | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin)['size'])")
[ "${MSA:-0}" -ge 1 ] && ok "tx ada di mempool A" || bad "mempool A kosong"
sleep 2
MSB=$(rpc $B_RPC getmempoolinfo | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin)['size'])")
MSC=$(rpc $C_RPC getmempoolinfo | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin)['size'])")
echo "   mempool B=$MSB C=$MSC"
[ "${MSB:-0}" -ge 1 ] && ok "tx ter-relay ke mempool B" || bad "tx tidak sampai ke B"
[ "${MSC:-0}" -ge 1 ] && ok "tx ter-relay ke mempool C" || bad "tx tidak sampai ke C"

echo "== 6. mining: tx masuk block, B menerima UTXO =="
rpc $A_RPC startmining >/dev/null 2>&1
for i in $(seq 1 30); do
    H2=$(rpc $A_RPC getblockcount | rpc_result | tr -d '"')
    [ "${H2:-0}" -gt "$H" ] 2>/dev/null && break
    sleep 1
done
echo "   A height: ${H2:-?} (sebelumnya $H)"
[ "${H2:-0}" -gt "$H" ] && ok "block baru di-mine (berisi tx)" || bad "tidak ada block baru"
# stop mining, biarkan B/C mengejar height final
rpc $A_RPC stopmining >/dev/null 2>&1
sleep 2
H2F=$(rpc $A_RPC getblockcount | rpc_result | tr -d '"')
for i in $(seq 1 60); do
    HB2=$(rpc $B_RPC getblockcount | rpc_result | tr -d '"')
    [ "${HB2:-0}" = "$H2F" ] 2>/dev/null && break
    sleep 1
done
echo "   B height: ${HB2:-?} (A final $H2F)"
BAL=$(rpc $B_RPC getbalance | rpc_result | python3 -c "import sys,json;print(json.load(sys.stdin).get('confirmed',0))")
echo "   B balance confirmed: $BAL"
[ "${BAL:-0}" -ge 150000000 ] && ok "B menerima 1.5 CDX (confirmed)" || bad "balance B salah ($BAL)"

echo "== 7. konsensus akhir =="
rpc $A_RPC stopmining >/dev/null 2>&1
sleep 2
HA_FINAL=$(rpc $A_RPC getblockcount | rpc_result | tr -d '"')
for i in $(seq 1 60); do
    HB2=$(rpc $B_RPC getblockcount | rpc_result | tr -d '"')
    HC2=$(rpc $C_RPC getblockcount | rpc_result | tr -d '"')
    [ "${HB2:-0}" = "$HA_FINAL" ] && [ "${HC2:-0}" = "$HA_FINAL" ] 2>/dev/null && break
    sleep 1
done
echo "   A=$HA_FINAL B=${HB2:-?} C=${HC2:-?}"
[ "${HB2:-0}" = "$HA_FINAL" ] && [ "${HC2:-0}" = "$HA_FINAL" ] && ok "B dan C mengejar height final $HA_FINAL" || bad "B/C tidak mengejar (B=$HB2 C=$HC2 A=$HA_FINAL)"
TA2=$(rpc $A_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bestblockhash'])")
TB2=$(rpc $B_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bestblockhash'])")
TC2=$(rpc $C_RPC getblockchaininfo | rpc_result | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bestblockhash'])")
[ "$TA2" = "$TB2" ] && [ "$TA2" = "$TC2" ] && ok "semua node setuju pada tip setelah mining" || bad "tip divergen setelah mining"

echo ""
echo "=================================================="
echo "HASIL: $PASS PASS, $FAIL FAIL"
echo "=================================================="
exit $FAIL
