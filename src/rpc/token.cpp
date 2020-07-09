// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <coins.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <hash.h>
#include <masternode.h>
#include <net_processing.h>
#include <netbase.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <util.h>
#include <utilstrencodings.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>


#include <stdint.h>

#include <univalue.h>

#include <kernel.h>
#include <miner.h>


#include <boost/thread/thread.hpp> // boost::thread::interrupt

#include <condition_variable>
#include <memory>
#include <mutex>

#include <boost/tokenizer.hpp>
#include <fstream>

#include <galaxycash.h>


UniValue istoken(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "istoken \"hash\"\n"
            "\nCommand to check token by id\n"

            "\nArguments:\n"
            "1. \"hash\"        (string) hash\n");


    return pgdb->HaveToken(uint256S(request.params[0].get_str()));
}

UniValue tokenidbyname(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokenidbyname \"name\"\n"
            "\nCommand to get token id by name\n"

            "\nArguments:\n"
            "1. \"name\"        (string) name of token\n");


    return pgdb->TokenIdByName(request.params[0].get_str()).GetHex();
}

UniValue tokenidbysymbol(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokenidbysymbol \"symbol\"\n"
            "\nCommand to get token id by symbol\n"

            "\nArguments:\n"
            "1. \"name\"        (string) symbol of token\n");


    return pgdb->TokenIdBySymbol(request.params[0].get_str()).GetHex();
}

UniValue tokeninfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokeninfo \"hash\"\n"
            "\nCommand to get token information by hash\n"

            "\nArguments:\n"
            "1. \"hash\"        (string) hash\n");

    GalaxyCashToken tokenInfo;
    if (pgdb->AccessToken(uint256S(request.params[0].get_str()), tokenInfo)) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("id", tokenInfo.GetHash().GetHex()));
        obj.push_back(Pair("name", tokenInfo.name));
        obj.push_back(Pair("symbol", tokenInfo.symbol));
        obj.push_back(Pair("supply", ValueFromAmount(tokenInfo.supply)));
        uint256 genesisTx;
        if (pgdb->GetGenesisTx(tokenInfo.GetHash(), genesisTx))
            obj.push_back(Pair("txid", genesisTx.GetHex()));
        return obj;
    }
    return false;
}

UniValue tokenlist(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "tokenlist\n"
            "\nCommand to get registred tokens list\n");

    UniValue list(UniValue::VARR);
    std::vector<uint256> tokens;
    pgdb->GetTokens(tokens);
    {
        for (size_t i = 0; i < tokens.size(); i++) 
            list.push_back(tokens[i].GetHex());
    }
    return list;
}


UniValue txtoken(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "txtoken \"txid\"\n"
            "\nCommand to get token id for tx\n");

    uint256 token;
    if (pgdb->GetTxToken(uint256S(request.params[0].get_str()), token)) {
        return token.GetHex();
    } else
        return NullUniValue;
}


static const CRPCCommand commands[] =
    {
        //  category              name                      actor (function)         okSafe argNames
        //  --------------------- ------------------------  -----------------------  ------ ----------
        {"token", "istoken", &istoken, {"hash"}},
        {"token", "tokeninfo", &tokeninfo, {"hash"}},
        {"token", "tokenidbyname", &tokenidbyname, {"name"}},
        {"token", "tokenidbysymbol", &tokenidbysymbol, {"symbol"}},
        {"token", "txtoken", &txtoken, {"txid"}},
        {"token", "tokenlist", &tokenlist, {}},
};

void RegisterTokenRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
