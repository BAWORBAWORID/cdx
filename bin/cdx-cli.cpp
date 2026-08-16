#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include "cli/commands.h"

using namespace cdx;

static void PrintUsage() {
    std::printf(
        "CDX CLI — Codex Coin\n"
        "Usage: cdx-cli [options] <command>\n"
        "\n"
        "Options:\n"
        "  -network=<mainnet|testnet|regtest>\n"
        "  -rpcuser=<user> -rpcpassword=<pass>\n"
        "  -datadir=<path>\n"
        "\n"
        "Commands:\n"
        "  blockchain info | height | sync | getblock <hash>\n"
        "  wallet create | getnewaddress | listaddresses | balance | history\n"
        "  wallet backup <password> | wallet restore <file> <password>\n"
        "  wallet lock | wallet unlock <password> | wallet rescan\n"
        "  send <address> <amount>\n"
        "  mining start | stop | status | setaddress <addr> | getaddress\n"
        "  network info | peers | connect <host:port>\n"
        "  mempool\n");
}

int main(int argc, char** argv) {
    CliConfig cfg;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("-network=", 0) == 0) cfg.network = a.substr(9);
        else if (a.rfind("-rpcuser=", 0) == 0) cfg.rpcUser = a.substr(9);
        else if (a.rfind("-rpcpassword=", 0) == 0) cfg.rpcPassword = a.substr(13);
        else if (a.rfind("-rpcport=", 0) == 0) cfg.rpcPort = a.substr(9);
        else if (a.rfind("-datadir=", 0) == 0) cfg.dataDir = a.substr(9);
        else if (a == "-h" || a == "-help" || a == "--help") { PrintUsage(); return 0; }
        else args.push_back(a);
    }
    if (args.empty()) {
        PrintUsage();
        return 1;
    }
    return RunCliCommand(cfg, args);
}
