#include "testfw.h"
#include "mempool/mempool.h"
#include "consensus/validation.h"
#include "script/interpreter.h"
#include "wallet/keypair.h"
#include "wallet/signer.h"
#include "transaction/serializer.h"
#include <cstring>

using namespace cdx;

static CCoinsView MakeFundedView(const uint8_t hash160[20], const COutPoint& fp, int64_t value) {
    CCoinsView view;
    CUTXO coin;
    coin.value = value;
    coin.scriptPubKey = BuildP2PKHScript(hash160);
    coin.height = 0;
    coin.isCoinbase = false;
    view.AddCoin(fp, coin);
    return view;
}

TEST(mempool_add_and_relay) {
    CKeyPair kp = CKeyPair::Generate(0x1E);
    COutPoint fp{uint256(100), 0};
    CCoinsView view = MakeFundedView(kp.hash160, fp, 1000000000LL);

    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout = fp;
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 999000000LL;
    out.scriptPubKey = BuildP2PKHScript(kp.hash160);
    tx.vout.push_back(out);
    std::string e;
    SignInput(tx, 0, kp, view.utxo[fp].scriptPubKey, e);

    CTxMemPool pool;
    int64_t fee = 0;
    std::string error;
    CHECK(pool.CheckTx(tx, view, 100, fee, error));
    CHECK(fee == 1000000LL);
    CHECK(pool.AddUnchecked(tx, fee, 100, 12345));
    CHECK(pool.Size() == 1);
    CHECK(pool.Exists(GetTxID(tx)));
    // duplikat -> gagal
    CHECK(!pool.AddUnchecked(tx, fee, 100, 12346));
}

TEST(mempool_double_spend) {
    CKeyPair kp = CKeyPair::Generate(0x1E);
    COutPoint fp{uint256(101), 0};
    CCoinsView view = MakeFundedView(kp.hash160, fp, 1000000000LL);

    auto makeTx = [&](int64_t amt) {
        CTransaction t;
        t.version = 1;
        CTxIn in;
        in.prevout = fp;
        t.vin.push_back(in);
        CTxOut out;
        out.value = amt;
        out.scriptPubKey = BuildP2PKHScript(kp.hash160);
        t.vout.push_back(out);
        std::string e;
        SignInput(t, 0, kp, view.utxo[fp].scriptPubKey, e);
        return t;
    };

    CTransaction t1 = makeTx(900000000LL);
    CTransaction t2 = makeTx(950000000LL);

    CTxMemPool pool;
    int64_t fee = 0;
    std::string error;
    CHECK(pool.CheckTx(t1, view, 100, fee, error));
    pool.AddUnchecked(t1, fee, 100, 1);
    // t2 menghabiskan input yang sama -> double spend
    CHECK(!pool.CheckTx(t2, view, 100, fee, error));
    CHECK(!error.empty());
}

TEST(mempool_remove_conflicts) {
    CKeyPair kp = CKeyPair::Generate(0x1E);
    COutPoint fp{uint256(102), 0};
    CCoinsView view = MakeFundedView(kp.hash160, fp, 1000000000LL);
    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout = fp;
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 999000000LL;
    out.scriptPubKey = BuildP2PKHScript(kp.hash160);
    tx.vout.push_back(out);
    std::string e;
    SignInput(tx, 0, kp, view.utxo[fp].scriptPubKey, e);
    CTxMemPool pool;
    int64_t fee = 0;
    std::string err;
    pool.CheckTx(tx, view, 100, fee, err);
    pool.AddUnchecked(tx, fee, 100, 1);
    CHECK(pool.Size() == 1);
    pool.RemoveConflicts(tx);
    CHECK(pool.Size() == 0);
}
