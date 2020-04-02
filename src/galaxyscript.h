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


class CScriptObject {
public:
    size_t refCounter;

    CScriptObject();
    CScriptObject(CScriptObject *value);
    virtual ~CScriptObject();

    CScriptObject *Grab() {
        refCounter++;
        return this;
    }
    CScriptObject *Drop() {
        if (refCounter == 1) {
            delete this;
            return nullptr;
        }
        refCounter--;
        return this;
    }

    virtual CScriptObject *Object() { return this; }
    virtual CScriptObject *Scope() { return this; }
    virtual CScriptObject *Value() { return this; }
 };

class CScriptVariable : public CScriptObject {
public:
    std::string name;
    CScriptObject *owner;
    CScriptObject *value;

    CScriptVariable();
    CScriptVariable(CScriptVariable *value);
    virtual ~CScriptVariable();

    virtual CScriptObject *Scope() { return owner; }
    virtual CScriptObject *Value() { return value; }
};

class CScriptStack : public std::vector<CScriptObject*> {
public:
    CScriptStack() {}
    CScriptStack(const CScriptStack &stack) : std::vector<CScriptObject*>(stack) {}
    CScriptStack(const std::vector<CScriptObject*> &stack) : std::vector<CScriptObject*>(stack) {}
    ~CScriptStack() {
        for (size_t i = 0; i < size(); i++)
            if ((*this)[i]) (*this)[i]->Drop();
    }

    bool IsEmpty() const {
        return empty();
    }
    
    CScriptObject *Push(CScriptObject *object) {
        push_back(object->Grab());
        return back()->Grab();
    }

    CScriptObject *Pop() {
        CScriptObject *object = back();
        pop_back();
        return object;
    }
    
    CScriptObject *Top() {
        return back()->Grab();
    }    
};

#endif