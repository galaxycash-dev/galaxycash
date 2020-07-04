// Copyright (c) 2020 GalaxyCash Developers
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

static std::string str_tolower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), 
                   [](unsigned char c){ return std::tolower(c); } // correct
                  );
    return s;
}

GalaxyCashDB::GalaxyCashDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "gdb", nCacheSize, fMemory, fWipe)
{
}


bool GalaxyCashDB::AddToken(const GalaxyCashToken& token)
{
    uint256 hash = token.GetHash();
    if (Exists(hash)) return false;

    
    if (!Write(hash, token)) return false;
    std::string str = token.name; str_tolower(str);
    uint256 hash2 = SerializeHash(str + "-nm");
    if (!Write(hash2, hash)) return false;
    str = token.symbol; str_tolower(str);
    hash2 = SerializeHash(str + "-sym");
    if (!Write(hash2, hash)) return false;

    return true;
}

bool GalaxyCashDB::SetToken(const uint256 &hash, const GalaxyCashToken& token)
{
    if (!Write(hash, token)) return false;
    std::string str = token.name; str_tolower(str);
    uint256 hash2 = SerializeHash(str + "-nm");
    if (!Write(hash2, hash)) return false;
    str = token.symbol; str_tolower(str);
    hash2 = SerializeHash(str + "-sym");
    if (!Write(hash2, hash)) return false;

    return true;
}

bool GalaxyCashDB::RemoveToken(const uint256 &hash)
{
    if (!Exists(hash)) return false;

    GalaxyCashToken token;
    if (AccessToken(hash, token)) {
        Erase(hash);
        std::string str = token.name; str_tolower(str);
        Erase(SerializeHash(str + "-nm"));
        str = token.symbol; str_tolower(str);
        Erase(SerializeHash(str + "-sym"));
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
    std::string str2 = str; str_tolower(str2);
    uint256 hash = SerializeHash(str2 + "-nm");
    uint256 hash2;
    if (Read(hash, hash2)) return Read(hash2, token);
    return false;
}

bool GalaxyCashDB::AccessTokenBySymbol(const std::string &str, GalaxyCashToken& token)
{
    std::string str2 = str; str_tolower(str2);

    uint256 hash = SerializeHash(str2 + "-sym");
    uint256 hash2;
    if (Read(hash, hash2)) return Read(hash2, token);
    return false;
}

bool GalaxyCashDB::HaveToken(const uint256 &hash)
{
    return Exists(hash);
}
