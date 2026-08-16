cmake_minimum_required(VERSION 3.16)
project(cdx VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(CDX_SOURCES
  src/config/networks.cpp
  src/crypto/uint256.cpp
  src/crypto/hash.cpp
  src/crypto/ripemd160.cpp
  src/crypto/encoding.cpp
  src/crypto/keys.cpp
  src/script/opcodes.cpp
  src/script/interpreter.cpp
  src/transaction/transaction.cpp
  src/transaction/serializer.cpp
  src/blockchain/merkle.cpp
  src/blockchain/block.cpp
  src/blockchain/genesis.cpp
  src/consensus/rules.cpp
  src/consensus/rewards.cpp
  src/consensus/difficulty.cpp
  src/consensus/chainwork.cpp
  src/consensus/validation.cpp
  src/consensus/policy.cpp
  src/utxo/utxo-set.cpp
  src/utxo/coin-selection.cpp
  src/mempool/mempool.cpp
  src/mempool/policy.cpp
  src/wallet/keypair.cpp
  src/wallet/address.cpp
  src/wallet/signer.cpp
  src/wallet/keystore.cpp
  src/wallet/wallet.cpp
  src/wallet/backup.cpp
  src/wallet/recovery.cpp
  src/mining/pow.cpp
  src/mining/miner.cpp
  src/blockchain/blockchain.cpp
  src/blockchain/reorg.cpp
  src/storage/blocks.cpp
  src/storage/chainstate.cpp
  src/storage/peers.cpp
  src/p2p/protocol.cpp
  src/p2p/peer.cpp
  src/p2p/server.cpp
  src/p2p/sync.cpp
  src/rpc/server.cpp
  src/rpc/methods.cpp
  src/cli/commands.cpp
)

add_library(cdxcore STATIC ${CDX_SOURCES})
target_include_directories(cdxcore PUBLIC src)
target_link_libraries(cdxcore PUBLIC OpenSSL::Crypto Threads::Threads)

add_executable(cdxd bin/cdxd.cpp)
target_link_libraries(cdxd PRIVATE cdxcore)

add_executable(cdx-cli bin/cdx-cli.cpp)
target_link_libraries(cdx-cli PRIVATE cdxcore)

add_executable(cdx-genesis bin/cdx-genesis.cpp)
target_link_libraries(cdx-genesis PRIVATE cdxcore)

enable_testing()

add_executable(test_cdx tests/test_main.cpp
  tests/test_crypto.cpp
  tests/test_uint256.cpp
  tests/test_serialization.cpp
  tests/test_transaction.cpp
  tests/test_merkle.cpp
  tests/test_block.cpp
  tests/test_consensus.cpp
  tests/test_wallet.cpp
  tests/test_mempool.cpp
  tests/test_storage.cpp
  tests/test_mining.cpp
  tests/test_chain.cpp
)
target_link_libraries(test_cdx PRIVATE cdxcore)
add_test(NAME test_cdx COMMAND test_cdx)
