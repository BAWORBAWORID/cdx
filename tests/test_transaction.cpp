#include "testfw.h"
#include "transaction/serializer.h"
#include "consensus/validation.h"
#include "script/interpreter.h"
#include "wallet/keypair.h"
#include "wallet/signer.h"
#include "crypto/encoding.h"
#include <cstring>

using namespace cdx;

TEST(coinbase_detection) {
    CTransaction tx;
    CTxIn in;
    in.prevout.hash.clear();
    in.prevout.n = 0xffffffff;
    tx.vin.push_back(in);
    CHECK(tx.IsCoinBase());
    tx.vin[0].prevout.n = 0;
    CHECK(!tx.IsCoinBase());
}

TEST(p2pkh_script_build) {
    uint8_t h[20] = {0};
    for (int i = 0; i < 20; ++i) h[i] = (uint8_t)i;
    auto script = BuildP2PKHScript(h);
    CHECK(script.size() == 25);
    CHECK(IsP2PKHScript(script));
    uint8_t h2[20];
    CHECK(ExtractP2PKHHash(script, h2));
    CHECK(std::memcmp(h, h2, 20) == 0);
}

TEST(sign_verify_transaction) {
    // buat keypair
    CKeyPair kp = CKeyPair::Generate(0x1E);
    CHECK(kp.IsValid());
    CHECK(!kp.address.empty());

    // coinbase -> UTXO
    CTransaction coinbase;
    coinbase.version = 1;
    CTxIn cbIn;
    cbIn.prevout.hash.clear();
    cbIn.prevout.n = 0xffffffff;
    cbIn.scriptSig = {0x04, 0x01, 0x02, 0x03, 0x04};
    coinbase.vin.push_back(cbIn);
    CTxOut cbOut;
    cbOut.value = 5000000000LL;
    cbOut.scriptPubKey = BuildP2PKHScript(kp.hash160);
    coinbase.vout.push_back(cbOut);

    CCoinsView view;
    COutPoint cbPoint{GetTxID(coinbase), 0};
    CUTXO cbCoin;
    cbCoin.value = cbOut.value;
    cbCoin.scriptPubKey = cbOut.scriptPubKey;
    cbCoin.height = 0;
    cbCoin.isCoinbase = true;
    view.AddCoin(cbPoint, cbCoin);

    // spend: kirim ke keypair lain
    CKeyPair recv = CKeyPair::Generate(0x1E);
    CTransaction spend;
    spend.version = 1;
    CTxIn in;
    in.prevout = cbPoint;
    spend.vin.push_back(in);
    CTxOut out;
    out.value = 4900000000LL;
    out.scriptPubKey = BuildP2PKHScript(recv.hash160);
    spend.vout.push_back(out);

    // sign
    std::string serr;
    CHECK(SignInput(spend, 0, kp, cbOut.scriptPubKey, serr));

    // validasi
    int64_t fee = 0;
    std::string error;
    // coinbase belum mature di height 1
    CHECK(!CheckTxInputs(spend, view, 1, fee, error));
    CHECK(!error.empty());
    // mature di height 120+
    CHECK(CheckTxInputs(spend, view, 120, fee, error));
    CHECK(fee == 100000000LL); // 100_000_000 base = 1 CDX fee

    // verifikasi signature rusak
    CTransaction bad = spend;
    bad.vin[0].scriptSig.clear();
    CHECK(!CheckTxInputs(bad, view, 120, fee, error));
}

TEST(double_spend_detection) {
    CKeyPair kp = CKeyPair::Generate(0x1E);
    CCoinsView view;
    // fund
    CTransaction fund;
    fund.version = 1;
    CTxIn cbIn;
    cbIn.prevout.hash.clear();
    cbIn.prevout.n = 0xffffffff;
    cbIn.scriptSig = {0x01, 0x01};
    fund.vin.push_back(cbIn);
    CTxOut fOut;
    fOut.value = 10000000000LL;
    fOut.scriptPubKey = BuildP2PKHScript(kp.hash160);
    fund.vout.push_back(fOut);
    COutPoint fp{GetTxID(fund), 0};
    CUTXO fCoin;
    fCoin.value = fOut.value;
    fCoin.scriptPubKey = fOut.scriptPubKey;
    fCoin.height = 0;
    fCoin.isCoinbase = false;
    view.AddCoin(fp, fCoin);

    // dua tx spend output yang sama
    auto makeSpend = [&](int64_t amt) {
        CTransaction t;
        t.version = 1;
        CTxIn in;
        in.prevout = fp;
        t.vin.push_back(in);
        CTxOut o;
        o.value = amt;
        o.scriptPubKey = BuildP2PKHScript(kp.hash160);
        t.vout.push_back(o);
        std::string e;
        SignInput(t, 0, kp, fOut.scriptPubKey, e);
        return t;
    };
    CTransaction t1 = makeSpend(1000000);
    CTransaction t2 = makeSpend(2000000);
    int64_t fee = 0;
    std::string error;
    CHECK(CheckTxInputs(t1, view, 1, fee, error));
    // double spend: output sudah dipakai t1
    CCoinsView view2 = view;
    view2.SpendCoin(fp);
    CHECK(!CheckTxInputs(t2, view2, 1, fee, error));
    CHECK(!error.empty());
}

TEST(transaction_size_limits) {
    CTransaction tx;
    CTxIn in;
    in.prevout.hash = uint256(1);
    tx.vin.push_back(in);
    CTxOut out;
    out.value = 1;
    out.scriptPubKey = BuildP2PKHScript(std::vector<uint8_t>(20, 1).data());
    tx.vout.push_back(out);
    std::string error;
    CHECK(CheckTransaction(tx, error));
    // empty vin -> invalid
    CTransaction bad;
    bad.vout.push_back(out);
    CHECK(!CheckTransaction(bad, error));
}
