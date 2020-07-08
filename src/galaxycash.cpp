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

#include <chain.h>
#include <validation.h>

std::unique_ptr<GalaxyCashDB> pgdb;

static std::string str_tolower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), 
                   [](unsigned char c){ return std::tolower(c); } // correct
                  );
    return s;
}

bool GalaxyCashToken::IsNative() const {
    return (str_tolower(symbol) == "gch")  || (str_tolower(name) == "galaxycash");
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

    std::vector<uint256> tokens;
    GetTokens(tokens);
    tokens.push_back(hash);
    SetTokens(tokens);

    return true;
}

bool GalaxyCashDB::SetToken(const uint256 &hash, const GalaxyCashToken& token)
{
    if (hash.IsNull()) return false;

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
    if (hash.IsNull()) return true;
    if (!Exists(hash)) return false;

    GalaxyCashToken token;
    if (AccessToken(hash, token)) {
        Erase(hash);
        std::string str = token.name; str_tolower(str);
        Erase(SerializeHash(str + "-nm"));
        str = token.symbol; str_tolower(str);
        Erase(SerializeHash(str + "-sym"));

        std::vector<uint256> tokens;
        GetTokens(tokens);

        std::vector<uint256>::iterator it = std::find(tokens.begin(), tokens.end(), hash);
        if (it != tokens.end()) tokens.erase(it);

        SetTokens(tokens);

        return true;
    }
    return false;
}

bool GalaxyCashDB::AccessToken(const uint256 &hash, GalaxyCashToken& token)
{
    if (hash.IsNull()) {
        token.name = "GalaxyCash";
        token.symbol = "GCH";
        token.supply = chainActive.Tip() ? chainActive.Tip()->nMoneySupply : 0;
        return true;
    }
    return Read(hash, token);
}

bool GalaxyCashDB::AccessTokenByName(const std::string &str, GalaxyCashToken& token)
{
    if (str_tolower(str) == "galaxycash") {
        token.name = "GalaxyCash";
        token.symbol = "GCH";
        token.supply = chainActive.Tip() ? chainActive.Tip()->nMoneySupply : 0;
        return true;
    }

    std::string str2 = str; str_tolower(str2);
    uint256 hash = SerializeHash(str2 + "-nm");
    uint256 hash2;
    if (Read(hash, hash2)) return Read(hash2, token);
    return false;
}

bool GalaxyCashDB::AccessTokenBySymbol(const std::string &str, GalaxyCashToken& token)
{
    if (str_tolower(str) == "gch") {
        token.name = "GalaxyCash";
        token.symbol = "GCH";
        token.supply = chainActive.Tip() ? chainActive.Tip()->nMoneySupply : 0;
        return true;
    }

    std::string str2 = str; str_tolower(str2);

    uint256 hash = SerializeHash(str2 + "-sym");
    uint256 hash2;
    if (Read(hash, hash2)) return Read(hash2, token);
    return false;
}

uint256 GalaxyCashDB::TokenIdByName(const std::string &str) {
    if (str_tolower(str) == "galaxycash") return uint256();

    uint256 hash = SerializeHash(str + "-nm");
    uint256 hash2;
    if (Read(hash, hash2)) return hash2;
    return uint256();
}

uint256 GalaxyCashDB::TokenIdBySymbol(const std::string &str) {
    if (str_tolower(str) == "gch") return uint256();

    uint256 hash = SerializeHash(str + "-sym");
    uint256 hash2;
    if (Read(hash, hash2)) return hash2;
    return uint256();
}

bool GalaxyCashDB::HaveToken(const uint256 &hash)
{
    if (hash.IsNull()) return true;
    return Exists(hash);
}

bool GalaxyCashDB::SetTxToken(const uint256 &hash, const uint256 &token) {
    return Write(SerializeHash(hash.GetHex() + "-tx"), token);
}

bool GalaxyCashDB::GetTxToken(const uint256 &hash, uint256 &token) {
    return Read(SerializeHash(hash.GetHex() + "-tx"), token);
}

bool GalaxyCashDB::SetGenesisTx(const uint256 &token, const uint256 &txid) {
    return Write(SerializeHash(token.GetHex() + "-genesis"), txid);
}

bool GalaxyCashDB::GetGenesisTx(const uint256 &token, uint256 &txid) {
    if (token.IsNull()) {
        txid = uint256S("a3df636e1166133b477fad35d677e81ab93f9c9d242bcdd0e9955c9982615915");
        return true;
    }
    return Read(SerializeHash(token.GetHex() + "-genesis"), txid);
}

bool GalaxyCashDB::SetTokens(const std::vector<uint256> &tokens) {
    return Write(std::string("tokenlist"), tokens);
}

bool GalaxyCashDB::GetTokens(std::vector<uint256> &tokens) {
    bool fOk = Read(std::string("tokenlist"), tokens);
    if (std::find(tokens.begin(), tokens.end(), uint256S("0000000000000000000000000000000000000000000000000000000000000000")) == tokens.end()) tokens.push_back(uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
    return fOk;
}

void SetTokenInfo(CMutableTransaction &tx, const GalaxyCashToken &token) {
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << token;
    tx.data = std::vector<unsigned char>(s.uptr(), s.uptr() + s.size());
}

bool GetTokenInfo(const CMutableTransaction &tx, GalaxyCashToken &token) {
    if (tx.data.empty()) return false;
    CDataStream s(tx.data, SER_NETWORK, PROTOCOL_VERSION);
    s >> token;
    return true;
}

bool GetTokenInfo(const CTransaction &tx, GalaxyCashToken &token) {
    if (tx.data.empty()) return false;
    CDataStream s(tx.data, SER_NETWORK, PROTOCOL_VERSION);
    s >> token;
    return true;
}