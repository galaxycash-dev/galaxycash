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
            "\nCommand to check token by hash\n"

            "\nArguments:\n"
            "1. \"hash\"        (string) hash\n");


    return false;
}

UniValue tokeninfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokeninfo \"hash\"\n"
            "\nCommand to get token information by hash\n"

            "\nArguments:\n"
            "1. \"hash\"        (string) hash\n");


    return false;
}

UniValue tokenbalance(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokenbalance \"hash\" [address]\n"
            "\nCommand to get token balance by hash\n"

            "\nArguments:\n"
            "1. \"hash\"        (string) hash\n"
            "1. \"address\"     (string) address\n");


    return false;
}

UniValue newtoken(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "newtoken \"name\" \"ticker\" supply\n"
            "\nCommand to create new token\n"

            "\nArguments:\n"
            "1. \"name\"        (string) name of token\n"
            "2. \"symbol\"      (string) symbol of token\n"
            "3. supply          (integer) supply of token\n");


    return false;
}

UniValue tokentransfer(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokentransfer \"hash\" amount \"address\" [\"fromaddress\"]\n"
            "\nCommand to create new token\n"

            "\nArguments:\n"
            "1. \"hash\"        (string) token hash id\n"
            "2. amount          (integer) amount of transaction\n"
            "3. \"address\"     (string) recipient address\n"
            "4. \"fromaddress\" (string) sender address\n");


    return false;
}

static const CRPCCommand commands[] =
    {
        //  category              name                      actor (function)         okSafe argNames
        //  --------------------- ------------------------  -----------------------  ------ ----------
        {"token", "istoken", &istoken, {"hash"}},
        {"token", "newtoken", &newtoken, {"name", "symbol", "supply"}},
        {"token", "tokeninfo", &tokeninfo, {"hash"}},
        {"token", "tokenbalance", &tokenbalance, {"hash", "address"}},
        {"token", "tokentransfer", &tokentransfer, {"hash", "amount", "address", "fromaddress"}},
};

void RegisterTokenRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
