#include "testfw.h"
#include "storage/blocks.h"
#include "blockchain/block.h"
#include "blockchain/merkle.h"
#include "script/interpreter.h"
#include "transaction/serializer.h"
#include "crypto/encoding.h"
#include <filesystem>

using namespace cdx;

static CBlock MakeBlock(const uint256& prev, int64_t value, uint32_t ts) {
    CBlock blk;
    CTransaction cb;
    cb.version = 1;
    CTxIn in;
    in.prevout.hash.clear();
    in.prevout.n = 0xffffffff;
    in.scriptSig = {0x01, 0x01};
    cb.vin.push_back(in);
    CTxOut out;
    out.value = value;
    out.scriptPubKey = {0x51};
    cb.vout.push_back(out);
    blk.vtx.push_back(cb);
    blk.header.version = 1;
    blk.header.prevBlockHash = prev;
    blk.header.merkleRoot = ComputeMerkleRoot(blk.vtx);
    blk.header.timestamp = ts;
    blk.header.bits = 0x1d00ffff;
    return blk;
}

TEST(block_storage_roundtrip) {
    std::string dir = "/tmp/cdx-test-storage";
    std::filesystem::remove_all(dir);
    {
        CBlockStorage s(dir);
        CBlock b1 = MakeBlock(uint256(), 50 * COIN, 1000);
        CHECK(s.WriteBlock(b1, 0));
        CBlock b2 = MakeBlock(b1.GetHash(), 50 * COIN, 2000);
        CHECK(s.WriteBlock(b2, 1));
        CHECK(s.BlockCount() == 2);

        CBlock r1, r2;
        CHECK(s.ReadBlock(b1.GetHash(), r1));
        CHECK(s.ReadBlock(b2.GetHash(), r2));
        CHECK(r1.GetHash() == b1.GetHash());
        CHECK(r2.GetHash() == b2.GetHash());
        CHECK(r1.vtx.size() == 1);
        CHECK(s.HasBlock(b1.GetHash()));
        CHECK(!s.HasBlock(uint256(0xdead)));
    }
    // reload dari disk
    {
        CBlockStorage s(dir);
        CBlock b2;
        // baca semua block via index
        CHECK(s.BlockCount() == 2);
        std::filesystem::remove_all(dir);
    }
}

TEST(chainstate_roundtrip) {
    std::string dir = "/tmp/cdx-test-chainstate";
    std::filesystem::remove_all(dir);
    {
        CBlockStorage s(dir);
        CCoinsView view;
        COutPoint out{uint256(1), 0};
        CUTXO coin;
        coin.value = 123456789;
        coin.scriptPubKey = BuildP2PKHScript(std::vector<uint8_t>(20, 7).data());
        coin.height = 42;
        coin.isCoinbase = true;
        view.AddCoin(out, coin);
        COutPoint out2{uint256(2), 3};
        CUTXO coin2;
        coin2.value = 987;
        coin2.scriptPubKey = {0x51};
        coin2.height = 100;
        coin2.isCoinbase = false;
        view.AddCoin(out2, coin2);
        std::vector<uint256> byHeight{uint256(1), uint256(2), uint256(3)};
        CHECK(s.SaveChainState(view, 2, uint256(3), byHeight));

        CCoinsView loaded;
        int64_t height = -1;
        uint256 tip;
        std::vector<uint256> loadedByHeight;
        CHECK(s.LoadChainState(loaded, height, tip, loadedByHeight));
        CHECK(height == 2);
        CHECK(tip == uint256(3));
        CHECK(loadedByHeight.size() == 3);
        CHECK(loaded.utxo.size() == 2);
        CUTXO c;
        CHECK(loaded.GetCoin(out, c));
        CHECK(c.value == 123456789);
        CHECK(c.isCoinbase);
        CHECK(c.height == 42);
    }
    std::filesystem::remove_all(dir);
}

TEST(peers_roundtrip) {
    std::string dir = "/tmp/cdx-test-peers";
    std::filesystem::remove_all(dir);
    {
        CBlockStorage s(dir);
        std::vector<std::string> peers = {"1.2.3.4:19333", "5.6.7.8:19333"};
        CHECK(s.SavePeers(peers));
        auto loaded = s.LoadPeers();
        CHECK(loaded.size() == 2);
        CHECK(loaded[0] == "1.2.3.4:19333");
        CHECK(loaded[1] == "5.6.7.8:19333");
    }
    std::filesystem::remove_all(dir);
}
