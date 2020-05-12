// Copyright (c) 2017-2019 The GalaxyCash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef GALAXYCASH_EXT_SCRIPT_H
#define GALAXYCASH_EXT_SCRIPT_H

#include "hash.h"
#include "random.h"
#include "serialize.h"
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <serialize.h>
#include <streams.h>
#include <unordered_map>
#include <util.h>
#include <utilstrencodings.h>
#include <vector>
#include <stack>

// GalaxyCash Scripting engine


#include "compat/endian.h"


bool GSInit();
void GSShutdown();

bool GSCompileModule(const std::string &name, const std::string &filename);
bool GSExec(const std::string &code);
bool GSLoadBinary(const std::vector<uint8_t> &code);
bool GSExexBinary(const std::vector<uint8_t> &code);

class CVirtualMachine {
public:
    CVirtualMachine();
    virtual ~CVirtualMachine();

    bool Init();
    void Shutdown();

    bool Execute(const std::string &code);
    bool ExecuteFile(const std::string &filepath);

    bool Compile(const std::string &name, const std::string &path);
};

#endif