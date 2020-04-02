// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <chainparams.h>
#include <galaxycash.h>
#include <galaxyscript.h>
#include <hash.h>
#include <memory>
#include <pow.h>
#include <stack>
#include <stdint.h>
#include <uint256.h>
#include <util.h>

#define BIT(x) (1 << x)

std::string RandName()
{
    char name[17];
    memset(name, 0, sizeof(name));
    GetRandBytes((unsigned char*)name, sizeof(name) - 1);
    return name;
}
