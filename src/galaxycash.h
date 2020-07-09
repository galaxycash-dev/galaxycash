// Copyright (c) 2017-2019 The GalaxyCash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef GALAXYCASH_EXT_H
#define GALAXYCASH_EXT_H

// GalaxyCash Extended functionality

#include <chain.h>
#include <coins.h>
#include <dbwrapper.h>
#include <key.h>
#include <net.h>
#include <pubkey.h>


#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base58.h>

#include <primitives/transaction.h>

#include <serialize.h>

#include <galaxyscript.h>

#include <uint256.h>
#include <arith_uint256.h>



class GalaxyCashToken {
public:
    std::string name, symbol;
    int64_t supply;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(symbol);
        if (!(s.GetType() & SER_GETHASH)) READWRITE(supply);
    }

    GalaxyCashToken() : supply(0) { }
    GalaxyCashToken(const GalaxyCashToken& token) : name(token.name), symbol(token.symbol), supply(token.supply) {}

    GalaxyCashToken& operator=(const GalaxyCashToken& token)
    {
        name = token.name;
        symbol = token.symbol;
        supply = token.supply;
        return *this;
    }

    void SetNull()
    {
        name.clear();
        symbol.clear();
        supply = 0;
    }

    bool IsNull() const
    {
        return name.empty() || symbol.empty();
    }

    bool IsNative() const;

    uint256 GetHash() const { 
        if (IsNative()) return uint256();
        return SerializeHash(*this); 
    }
};


class GalaxyCashDB : public CDBWrapper
{
public:
    enum {
        MAX_POWWORKS = 100
    };

    GalaxyCashDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool SetTokens(const std::vector<uint256> &tokens);
    bool GetTokens(std::vector<uint256> &tokens);

    bool SetTxToken(const uint256 &txid, const uint256 &token);
    bool GetTxToken(const uint256 &txid, uint256 &token);

    bool SetGenesisTx(const uint256 &token, const uint256 &txid);
    bool GetGenesisTx(const uint256 &token, uint256 &txid);

    uint256 TokenIdByName(const std::string &str);
    uint256 TokenIdBySymbol(const std::string &str);

    bool AddToken(const GalaxyCashToken &token);
    bool SetToken(const uint256 &hash, const GalaxyCashToken &token);
    bool RemoveToken(const uint256 &hash);
    bool AccessToken(const uint256 &hash, GalaxyCashToken& token);
    bool HaveToken(const uint256 &hash);
    bool AccessTokenByName(const std::string& name, GalaxyCashToken& token);
    bool AccessTokenBySymbol(const std::string& symbol, GalaxyCashToken& token);
};
    
void SetTokenInfo(CMutableTransaction &tx, const GalaxyCashToken &token);
bool GetTokenInfo(const CMutableTransaction &tx, GalaxyCashToken &token);
bool GetTokenInfo(const CTransaction &tx, GalaxyCashToken &token);

extern std::unique_ptr<GalaxyCashDB> pgdb;
extern const int64_t g_token_collateral;

#endif
