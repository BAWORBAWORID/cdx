#include "testfw.h"
#include "wallet/wallet.h"
#include "wallet/backup.h"
#include "wallet/keypair.h"
#include "wallet/address.h"
#include "wallet/signer.h"
#include "consensus/validation.h"
#include "script/interpreter.h"
#include "transaction/serializer.h"
#include "crypto/encoding.h"
#include <cstring>
#include <filesystem>

using namespace cdx;

TEST(wallet_generate_independent_keypairs) {
    CWallet w;
    w.versionByte = 0x1E;
    CHECK(w.Unlock("testpassword"));
    CKeyPair a = w.GenerateNewAddress();
    CKeyPair b = w.GenerateNewAddress();
    CKeyPair c = w.GenerateNewAddress();
    CHECK(a.address != b.address);
    CHECK(b.address != c.address);
    CHECK(a.address != c.address);
    CHECK(w.KeyCount() == 3);
    CHECK(w.HasKey(a.address));
    CHECK(!w.HasKey("invalid"));
    // private keys berbeda (independen, bukan derivasi)
    uint8_t pa[32], pb[32];
    a.GetPrivKey(pa);
    b.GetPrivKey(pb);
    CHECK(std::memcmp(pa, pb, 32) != 0);
}

TEST(wallet_lock_unlock) {
    CWallet w;
    w.versionByte = 0x1E;
    CHECK(w.Unlock("pass123"));
    CKeyPair kp = w.GenerateNewAddress();
    CHECK(w.Lock());
    CHECK(w.IsLocked());
    CKey k;
    CHECK(!w.GetKey(kp.address, k)); // locked
    CHECK(w.Unlock("pass123"));
    CHECK(w.GetKey(kp.address, k));
    CHECK(k.IsValid());
    CHECK(!w.Unlock("wrongpass"));
}

TEST(wallet_balance_from_utxo) {
    CWallet w;
    w.versionByte = 0x1E;
    w.Unlock("pw");
    CKeyPair kp = w.GenerateNewAddress();

    CCoinsView view;
    // coinbase immature
    COutPoint cb{uint256(1), 0};
    CUTXO cbCoin;
    cbCoin.value = 5000000000LL;
    cbCoin.scriptPubKey = BuildP2PKHScript(kp.hash160);
    cbCoin.height = 0;
    cbCoin.isCoinbase = true;
    view.AddCoin(cb, cbCoin);
    // regular utxo
    COutPoint reg{uint256(2), 0};
    CUTXO regCoin;
    regCoin.value = 1000000000LL;
    regCoin.scriptPubKey = BuildP2PKHScript(kp.hash160);
    regCoin.height = 50;
    regCoin.isCoinbase = false;
    view.AddCoin(reg, regCoin);

    auto bal = w.GetBalance(view, 50);
    CHECK(bal.immature == 5000000000LL); // coinbase belum mature (120)
    CHECK(bal.confirmed == 1000000000LL);
    CHECK(bal.spendable == 1000000000LL);
    CHECK(bal.unconfirmed == 0);

    // setelah mature
    auto bal2 = w.GetBalance(view, 200);
    CHECK(bal2.immature == 0);
    CHECK(bal2.confirmed == 6000000000LL);
}

TEST(wallet_create_transaction) {
    CWallet w;
    w.versionByte = 0x1E;
    w.Unlock("pw");
    CKeyPair kp = w.GenerateNewAddress();
    CKeyPair recv = CKeyPair::Generate(0x1E);

    // fund wallet
    CCoinsView view;
    COutPoint fp{uint256(10), 0};
    CUTXO fCoin;
    fCoin.value = 2000000000LL; // 20 CDX
    fCoin.scriptPubKey = BuildP2PKHScript(kp.hash160);
    fCoin.height = 0;
    fCoin.isCoinbase = false;
    view.AddCoin(fp, fCoin);

    CTransaction tx;
    uint256 txid;
    std::string error;
    // kirim 5 CDX
    CHECK(w.CreateTransaction(view, 100, recv.address, 500000000LL, tx, txid, error));
    CHECK(!txid.isZero());
    CHECK(tx.vout.size() >= 1);
    // output pertama = penerima
    uint8_t rh[20];
    ExtractP2PKHHash(tx.vout[0].scriptPubKey, rh);
    CHECK(std::memcmp(rh, recv.hash160, 20) == 0);
    // valid terhadap view
    int64_t fee = 0;
    std::string verr;
    CHECK(CheckTxInputs(tx, view, 100, fee, verr));
    CHECK(fee >= 0);
    // change ada (input 20 CDX, output 5 + fee, change ~15)
    CHECK(tx.vout.size() == 2);
}

TEST(wallet_insufficient_funds) {
    CWallet w;
    w.versionByte = 0x1E;
    w.Unlock("pw");
    CKeyPair kp = w.GenerateNewAddress();
    CKeyPair recv = CKeyPair::Generate(0x1E);
    CCoinsView view;
    COutPoint fp{uint256(1), 0};
    CUTXO fCoin;
    fCoin.value = 1000000LL;
    fCoin.scriptPubKey = BuildP2PKHScript(kp.hash160);
    fCoin.height = 0;
    fCoin.isCoinbase = false;
    view.AddCoin(fp, fCoin);
    CTransaction tx;
    uint256 txid;
    std::string error;
    CHECK(!w.CreateTransaction(view, 100, recv.address, 999999999LL, tx, txid, error));
    CHECK(!error.empty());
}

TEST(wallet_backup_restore) {
    CWallet w;
    w.versionByte = 0x1E;
    w.Unlock("backuppw");
    CKeyPair a = w.GenerateNewAddress();
    CKeyPair b = w.GenerateNewAddress();
    CKeyPair c = w.GenerateNewAddress();

    auto backup = w.Backup("backuppw");
    CHECK(backup.size() > 0);

    std::string error;
    CWallet restored = CWallet::Restore(backup, "backuppw", error);
    CHECK(error.empty());
    CHECK(restored.KeyCount() == 3);
    CHECK(restored.HasKey(a.address));
    CHECK(restored.HasKey(b.address));
    CHECK(restored.HasKey(c.address));

    // private keys identical
    CKey k1, k2;
    restored.Unlock("backuppw");
    CHECK(w.GetKey(a.address, k1));
    CHECK(restored.GetKey(a.address, k2));
    uint8_t p1[32], p2[32];
    k1.GetPrivKey(p1);
    k2.GetPrivKey(p2);
    CHECK(std::memcmp(p1, p2, 32) == 0);

    // wrong password -> error
    CWallet bad = CWallet::Restore(backup, "wrong", error);
    CHECK(!error.empty());
    CHECK(bad.KeyCount() == 0);
}

TEST(wallet_wif_roundtrip) {
    CKeyPair kp = CKeyPair::Generate(0x1E);
    std::string wif = kp.GetWIF(0x1E);
    uint8_t v, priv[32];
    CHECK(WIFToPrivKey(wif, v, priv));
    CHECK(v == 0x1E);
    CKeyPair kp2 = CKeyPair::FromPrivKey(priv, 0x1E);
    CHECK(kp2.address == kp.address);
    // import ke wallet
    CWallet w;
    w.versionByte = 0x1E;
    w.Unlock("pw");
    CHECK(w.ImportWIF(wif));
    CHECK(w.HasKey(kp.address));
}

TEST(change_address_independent) {
    // setiap change address harus keypair independen baru
    CWallet w;
    w.versionByte = 0x1E;
    w.Unlock("pw");
    size_t before = w.KeyCount();
    CKeyPair a = w.GenerateNewAddress();
    CKeyPair b = w.GenerateNewAddress();
    CHECK(w.KeyCount() == before + 2);
    uint8_t pa[32], pb[32];
    a.GetPrivKey(pa);
    b.GetPrivKey(pb);
    CHECK(std::memcmp(pa, pb, 32) != 0);
}
