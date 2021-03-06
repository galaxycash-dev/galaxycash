// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>
#include <memory>

#include <init.h>

#include <chainparamsseeds.h>

#include <arith_uint256.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();
    txNew.nTime = nTimeTx;

    CBlock genesis;
    genesis.nTime = nTimeBlock;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    const char* pszTimestamp = "15/october/2017 The development of Galaxy Cash started.";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTimeTx, nTimeBlock, nNonce, nBits, nVersion);
}


CChainParams::CChainParams()
{
    pubKey = CPubKey(ParseHex("021ca96799378ec19b13f281cc8c2663714153aa58b70e4ce89460741c3b00b645"));
    key = CKey();
}

const CKey &CChainParams::DevKey() const {
    std::string devkey = gArgs.GetArg("-devkey", "");
    if (!key.IsValid() && !devkey.empty()) {
        CBitcoinSecret secret;
        if (!secret.SetString(devkey))
            return key;

        key = secret.GetKey();
        assert(pubKey == key.GetPubKey());
    }
    return key; 
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams
{
public:
    CMainParams() : CChainParams()
    {
        strNetworkID = "main";

        consensus.nLastPoW = 130000;
        consensus.nSubsidyHalvingInterval = 210000;

        consensus.BIP16Height = 0;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x000002e5d366c89b16195d618462f5ad14f8bbfaf39a93f2593c2ceb67d94c16");
        consensus.powLimit = uint256S("0x00000fffff000000000000000000000000000000000000000000000000000000");

        consensus.ECOHeight = 660000;
        consensus.SubsidyStopHeight = 600000;


        // POS
        consensus.stakeLimit = uint256S("0x00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPOSFirstBlock = 61300;
        consensus.nStakeMinConfirmations = 50;

        consensus.nTargetSpacing = 3 * 60;         // 3 minutes
        consensus.nTargetSpacing2 = 10 * 60;       // 10 minutes
        consensus.nTargetTimespan = 6 * 60 * 60;   // 6 hours
        consensus.nTargetTimespan2 = 24 * 60 * 60; // 24 hours
        consensus.nStakeTargetSpacing = 2 * 60;
        consensus.nStakeTargetTimespan = 6 * 60 * 60;                      // 6 hours
        consensus.nStakeMinAge = 6 * 60 * 60;                              // minimum age for coin age
        consensus.nStakeMaxAge = std::numeric_limits<int>::max();
        consensus.nModifierInterval = 5 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 11;

        // Merge
        consensus.nMergeFirstBlock = consensus.nCoinbaseMaturity + 2;
        consensus.nMergeLastBlock = 95;

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256("0x9a4004b1327ae419b54cf9afa360b0aece7abe21a5a01860f3e131afde31c037");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x4e;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xe6;
        pchMessageStart[3] = 0x4e;

        nDefaultPort = 7604;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1515086697, 1515086697, 1303736, UintToArith256(consensus.powLimit).GetCompact(), 9);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000076b947553b6888ca82875e04a4db21fd904aae46589e1d183b63327468"));
        assert(genesis.hashMerkleRoot == uint256S("0xa3df636e1166133b477fad35d677e81ab93f9c9d242bcdd0e9955c9982615915"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("5.63.158.141");
        vSeeds.emplace_back("31.40.218.121");
        vSeeds.emplace_back("204.12.216.234");
        vSeeds.emplace_back("188.154.210.90");
        vSeeds.emplace_back("141.226.9.42");
        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 38); // galaxycash: addresses begin with 'G'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 99);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 89);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x1D, 0x88, 0xB2, 0x23};
        base58Prefixes[EXT_SECRET_KEY] = {0x1D, 0x88, 0x2D, 0x56};

        // human readable prefix to bench32 address
        bech32_hrp = "gc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {{0, uint256S("0x00000076b947553b6888ca82875e04a4db21fd904aae46589e1d183b63327468")},
            {50000, uint256S("0x00000000000e1127bc6c06b1ec2a869b6bf2c51e35548640465bfd1759644e46")},
            {100000, uint256S("0x63f8e72c85a8c0cd5af7e60eb63bc0029942bb4ede87cf95899ce81b7775ca8e")},
            {150000, uint256S("0xb9562147971c3ae0a5f4f35cd696922e58734ad116edf04ef9e477f5566c0570")},
            {200000, uint256S("0x61b243b64f34d34696eebfb8e1a08a47f1854b8c6be511001871a0de061d5f31")},
            {250000, uint256S("0xdd13ab4b5bea63f1744eb2716231da560aaa98cf0eafe93d4890b063fd86415b")},
            {300000, uint256S("0x38ad3b008a319b0fd98fb9309b728628aeae8f1c0dd32a4c6b26647512500b49")},
            {350000, uint256S("0x849e4381fc9ed722e32d105f05a673f9431ac838d6200eb62dc01acb6a9df3f7")},
            {450000, uint256S("0xae77be762ec79fc75e4be9ad2c61f1cc477738b4d3b9bf568ae16208e254598e")},
            {466000, uint256S("0x9a4004b1327ae419b54cf9afa360b0aece7abe21a5a01860f3e131afde31c037")},
            {480000, uint256S("0xcdd2849b2781eaedaa6273a2ebd56c8827435e2d85f93861a9b50493ecf143ca")},
            {490000, uint256S("0xf9652d83e27d0e6bfc3e18894bdfb411013b9dc587b771b3579510b6de36d632")}}};


        chainTxData = ChainTxData{
            // Data as of block 9a4004b1327ae419b54cf9afa360b0aece7abe21a5a01860f3e131afde31c037 (height 466000).
            1575522400, // * UNIX timestamp of last known number of transactions
            898427,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.01491497937413473};
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams
{
public:
    CTestNetParams() : CChainParams()
    {
        strNetworkID = "test";

        consensus.nLastPoW = 13000000;
        consensus.nSubsidyHalvingInterval = 210000;

        consensus.BIP16Height = 0;
        consensus.BIP34Height = 293368;
        consensus.BIP34Hash = uint256S("00000002c0b976c7a5c9878f1cec63fb4d88d68d614aedeaf8158c42d904795e");
        consensus.powLimit =            uint256S("0000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 28;


        consensus.ECOHeight = 0;
        consensus.SubsidyStopHeight = 0;


        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256(); //1135275


        // POS
        consensus.stakeLimit = uint256S("0x00000fffff000000000000000000000000000000000000000000000000000000");

        consensus.nPOSFirstBlock = 0;
        consensus.nStakeMinConfirmations = 50;

        consensus.nTargetSpacing = 3 * 60;         // 3 minutes
        consensus.nTargetSpacing2 = 10 * 60;       // 10 minutes
        consensus.nTargetTimespan = 6 * 60 * 60;   // 6 hours
        consensus.nTargetTimespan2 = 24 * 60 * 60; // 24 hours
        consensus.nStakeTargetSpacing = 2 * 60;
        consensus.nStakeTargetTimespan = 6 * 60 * 60;                      // 6 hours
        consensus.nStakeMinAge = 6 * 60 * 60;                              // minimum age for coin age
        consensus.nStakeMaxAge = std::numeric_limits<int>::max();
        consensus.nModifierInterval = 5 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 11;

        // Merge
        consensus.nMergeFirstBlock =  consensus.nMergeLastBlock = 0;

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;



        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x4e;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xe6;
        pchMessageStart[3] = 0x4e;

        nDefaultPort = 17604;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1515086697, 1515086697, 1303736, UintToArith256(consensus.powLimit).GetCompact(), 9);
        consensus.hashGenesisBlock = genesis.GetHash();

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 38); // galaxycash: addresses begin with 'G'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 99);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 89);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x1D, 0x88, 0xB2, 0x23};
        base58Prefixes[EXT_SECRET_KEY] = {0x1D, 0x88, 0x2D, 0x56};

        // human readable prefix to bench32 address
        bech32_hrp = "gc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;


        checkpointData = {
            {}};

        chainTxData = ChainTxData{
            0,
            0,
            0};
    }
};

/**
 * Regression test
 */

class CRegTestParams : public CChainParams
{
public:
    CRegTestParams() : CChainParams()
    {
        strNetworkID = "regtest";
        consensus.BIP16Height = 0;         // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");            // ~arith_uint256(0) >> 28;

        consensus.nTargetTimespan = 7 * 24 * 60 * 60;                         // two weeks
        consensus.nStakeTargetSpacing = 10 * 60;                              // 10-minute block spacing
        consensus.nTargetSpacing = consensus.nStakeTargetSpacing;

        consensus.nStakeMinAge = 60 * 60 * 24; // test net min age is 1 day
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90;
        consensus.nModifierInterval = 60 * 20; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 60;

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xcb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;

        nDefaultPort = 27604;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1345083810, 1345090000, 122894938, 0x1d0fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        checkpointData = {
            {}};

        chainTxData = ChainTxData{
            0,
            0,
            0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "gcrt";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams& Params()
{
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
