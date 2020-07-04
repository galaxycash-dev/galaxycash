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



GalaxyCashDB::GalaxyCashDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "galaxycash" / "database", nCacheSize, fMemory, fWipe)
{
}


bool GalaxyCashDB::AddToken(const GalaxyCashToken& token)
{
    uint256 hash = token.GetHash();
    if (!Write(hash, token)) return false;
    uint256 hash2 = SerializeHash(token.name + "-name");
    if (!Write(hash2, hash)) return false;
    hash2 = SerializeHash(token.symbol + "-symbol");
    if (!Write(hash2, hash)) return false;

}

bool GalaxyCashDB::RemoveToken(const uint256 &hash)
{
    GalaxyCashToken token;
    if (AccessToken(hash, token)) {
        Erase(hash);
        Erase(SerializeHash(token.name + "-name"));
        Erase(SerializeHash(token.symbol + "-symbol"));
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
    uint256 hash = SerializeHash(str + "-name");
    return Read(hash, token);
}

bool GalaxyCashDB::AccessTokenBySymbol(const std::string &str, GalaxyCashToken& token)
{
    uint256 hash = SerializeHash(str + "-symbol");
    return Read(hash, token);
}

bool GalaxyCashDB::HaveToken(const uint256 &hash)
{
    return Exists(hash);
}


GalaxyCashDB *pgdb = nullptr;