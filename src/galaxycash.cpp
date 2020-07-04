// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <galaxycash.h>

#include <chainparams.h>
#include <hash.h>
#include <memory>
#include <pow.h>
#include <uint256.h>
#include <util.h>

#include <stdint.h>


std::unique_ptr<GalaxyCashDB> pgdb;

GalaxyCashDB::GalaxyCashDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "gdb", nCacheSize, fMemory, fWipe)
{
}


bool GalaxyCashDB::AddToken(const GalaxyCashToken& token)
{
    uint256 hash = token.GetHash();
    if (Exists(hash)) return false;

    
    if (!Write(hash, token)) return false;
    uint256 hash2 = SerializeHash(token.name + "-nm");
    if (!Write(hash2, hash)) return false;
    hash2 = SerializeHash(token.symbol + "-sym");
    if (!Write(hash2, hash)) return false;

    return true;
}

bool GalaxyCashDB::RemoveToken(const uint256 &hash)
{
    if (!Exists(hash)) return false;

    GalaxyCashToken token;
    if (AccessToken(hash, token)) {
        Erase(hash);
        Erase(SerializeHash(token.name + "-nm"));
        Erase(SerializeHash(token.symbol + "-sym"));
        return true;
    }
    return false;
}

bool GalaxyCashDB::AccessToken(const uint256 &hash, GalaxyCashToken& token)
{
    return Read(hash, token);
}

bool GalaxyCashDB::AccessTokenByName(const std::string &str, GalaxyCashToken& token)
{
    uint256 hash = SerializeHash(str + "-nm");
    return Read(hash, token);
}

bool GalaxyCashDB::AccessTokenBySymbol(const std::string &str, GalaxyCashToken& token)
{
    uint256 hash = SerializeHash(str + "-sym");
    return Read(hash, token);
}

bool GalaxyCashDB::HaveToken(const uint256 &hash)
{
    return Exists(hash);
}
