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
    int64_t supply, reward;
    bool minable;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(symbol);
        READWRITE(reward);
        READWRITE(minable);
        if (!(s.GetType() & SER_GETHASH)) READWRITE(supply);
    }

    GalaxyCashToken() : supply(0), reward(0), minable(false) { }
    GalaxyCashToken(const GalaxyCashToken& token) : name(token.name), symbol(token.symbol), supply(token.supply), reward(token.reward), minable(token.minable) {}

    GalaxyCashToken& operator=(const GalaxyCashToken& token)
    {
        name = token.name;
        symbol = token.symbol;
        supply = token.supply;
        reward = token.reward;
        minable = token.minable;
        return *this;
    }

    void SetNull()
    {
        name.clear();
        symbol.clear();
        supply = reward = 0;
        minable = false;
    }

    bool IsNull() const
    {
        return name.empty() || symbol.empty();
    }

    uint256 GetHash() const { return SerializeHash(*this); }
};

class GalaxyCashPoWWork {
public:
    uint256 hashPrevBlock;
    uint32_t nBits, nNonce, nExtraNonce;
    int64_t nValue;
    std::vector<unsigned char> vchWorkSig;

    GalaxyCashPoWWork() : nBits(0), nNonce(0), nExtraNonce(0), nValue(0) {}
    GalaxyCashPoWWork(const GalaxyCashPoWWork &work) : hashPrevBlock(work.hashPrevBlock), nBits(work.nBits), nNonce(work.nNonce), nExtraNonce(work.nExtraNonce), nValue(work.nValue), vchWorkSig(work.vchWorkSig) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(hashPrevBlock);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nExtraNonce);
        READWRITE(nValue);
        if (!(s.GetType() & SER_GETHASH)) READWRITE(vchWorkSig);
    }

    uint256 GetPoWHash() const { return HashX12(BEGIN(hashPrevBlock), END(nValue)); }
    uint256 GetHash() const { return SerializeHash(*this); }
};

class GalaxyCashDB : public CDBWrapper
{
public:
    enum {
        MAX_POWWORKS = 100
    };

    GalaxyCashDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool SetTxToken(const uint256 &txid, const uint256 &token);
    bool GetTxToken(const uint256 &txid, uint256 &token);

    bool AddToken(const GalaxyCashToken &token);
    bool SetToken(const uint256 &hash, const GalaxyCashToken &token);
    bool RemoveToken(const uint256 &hash);
    bool AccessToken(const uint256 &hash, GalaxyCashToken& token);
    bool HaveToken(const uint256 &hash);
    bool AccessTokenByName(const std::string& name, GalaxyCashToken& token);
    bool AccessTokenBySymbol(const std::string& symbol, GalaxyCashToken& token);

    bool SetPoWWorks(const uint256 &hash, const std::vector<GalaxyCashPoWWork> &works);
    bool GetPoWWorks(const uint256 &hash, std::vector<GalaxyCashPoWWork> &works);

    bool GenerateNextPoWWork(const uint256 &hash, GalaxyCashPoWWork &work);
};
    
void SetTokenInfo(CMutableTransaction &tx, const GalaxyCashToken &token);
bool GetTokenInfo(const CMutableTransaction &tx, GalaxyCashToken &token);
bool GetTokenInfo(const CTransaction &tx, GalaxyCashToken &token);

extern std::unique_ptr<GalaxyCashDB> pgdb;

#endif
