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

class CScriptVariable;

class CByteArray : public std::vector<uint8_t> {
public:
    CByteArray() {}
    CByteArray(const CByteArray &v) : std::vector<uint8_t>(v) {}
    CByteArray(const std::vector<uint8_t> &v) : std::vector<uint8_t>(v) {}

    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*this);
    }

};

class CScriptObject {
public:
    size_t refCounter;
    std::vector<CScriptVariable*> variables;

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

    virtual std::string TypeName() const { return "Object"; }

    virtual bool HasNull() const { return false; }
    virtual bool HasUndefined() const { return false; }
    virtual bool HasNullOrUndefined() const { return false; }

    virtual CScriptObject *Instance() { return this->Grab(); }
    virtual CScriptObject *Object() { return this->Grab(); }

    virtual void SetScope(CScriptObject *value) {}
    virtual CScriptObject *GetScope() { return this->Grab(); }

    virtual void SetValue(CScriptObject *value) {}
    virtual CScriptObject *GetValue() { return this->Grab(); }

    virtual CScriptVariable *Variable(const std::string &name);
    virtual CScriptVariable *Register(const std::string &name, CScriptObject *value);
};

class CScriptUndefined : public CScriptObject {
public:
    CScriptUndefined() {}
    virtual std::string TypeName() const { return "undefined"; }
    virtual bool HasUndefined() const { return true; }
    virtual bool HasNullOrUndefined() const { return true; }
};

class CScriptNull : public CScriptObject {
public:
    CScriptNull() {}
    virtual std::string TypeName() const { return "null"; }
    virtual bool HasNull() const { return true; }
    virtual bool HasNullOrUndefined() const { return true; }
};

class CScriptVariable : public CScriptObject {
public:
    std::string name;
    CScriptObject *owner;
    CScriptObject *value;

    CScriptVariable() {}
    CScriptVariable(CScriptVariable *value) {
        if (value) {
            this->name = value->name;
            this->owner = value->owner ? value->owner->Grab() : nullptr;
            this->value = value->value ? value->value->Grab() : nullptr;
        }
    }
    virtual ~CScriptVariable() {
        if (value) value->Drop();
        if (owner) owner->Drop();
    }

    virtual std::string TypeName() const { return value ? value->TypeName() : "undefined"; }
    virtual bool HasNull() const { return value ? value->HasNull() : false; }
    virtual bool HasUndefined() const { return value ? value->HasUndefined() : true; }
    virtual bool HasNullOrUndefined() const { return value ? value->HasNullOrUndefined() : true; }

    virtual CScriptObject *Instance() { return value ? value->Instance() : nullptr; }

    virtual void SetScope(CScriptObject *value) {
        if (this->owner) this->owner->Drop();
        this->owner = value;
        if (this->owner) this->owner->Grab();
    }
    virtual CScriptObject *GetScope() { return owner ? owner->Grab() : nullptr; }

    virtual void SetValue(CScriptObject *value) {
        if (this->value) this->value->Drop();
        this->value = value;
        if (this->value) this->value->Grab();
    }
    virtual CScriptObject *GetValue() { return value ? value->Grab() : nullptr; }

    virtual CScriptVariable *Variable(const std::string &name) {
        if (value && !value->HasNullOrUndefined()) return value->Variable(name);
        return nullptr;
    }
    virtual CScriptVariable *Register(const std::string &name, CScriptObject *value) {
        if (value && !value->HasNullOrUndefined()) return value->Register(name, value);
        return value ? value->Grab() : nullptr;
    }

    virtual std::string AsString() const { return ""; }
    virtual bool AsBoolean() const { return false; }
    virtual int64_t AsInteger() const { return 0; }
    virtual uint64_t AsUnsignedInteger() const { return 0; }
    virtual double AsFloat() const { return 0; }
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
    
    void Push(CScriptObject *object) {
        push_back(object->Grab());
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

class CScriptOpcode {
public:
    enum {
        NOP = 0,
        POP,
        DUP,

        INFO,
        RET,
        END,
        IMPORT,

        LABEL,
        BLOCK,
        CODE,

        NL,
        BYTES,
        STRING,
        BOOLEAN,
        INTEGER,
        FLOAT,
        OBJECT,
        ARRAY,
        FUNCTION,

        DECLARE,
        VARIABLE,
        PUSH,
        ELEMENT,
        LENGTH,

        ASSIGN,
        STORE,

        PLUS,
        MINUS,
        MULTIPLY,
        DIVIDE,
        MOD,
        AND,
        OR,
        XOR,

        NOT,
        NEG,
        TILDA,

        Z,
        NZ,

        EQ,
        NQ,

        LT,
        LQ,

        GT,
        GQ,

        NUM_OPCODES
    };
};

class CScriptCallable : public CScriptObject {
public:
    CByteArray code;

    virtual bool Call(CScriptStack *stack);

    void InstrNop(CScriptStack *stack);
    void InstrPop(CScriptStack *stack);
    void InstrDup(CScriptStack *stack);

    void InstrNull(CScriptStack *stack);
    void InstrString(CScriptStack *stack);
    void InstrBoolean(CScriptStack *stack);
    void InstrInteger(CScriptStack *stack);
    void InstrFloat(CScriptStack *stack);
};

class CScriptFunction : public CScriptCallable {
public:
    virtual bool Call(CScriptStack *stack);
};

class CScriptConsoleLog : public CScriptFunction {
public:
    virtual bool Call(CScriptStack *stack) {
        if (stack->IsEmpty()) return false;
        CScriptObject *val = stack->Pop();
        LogPrintStr(val->AsString()); val->Drop();
        return true;
    }

    virtual CScriptObject *Instance() {
        static CScriptConsoleLog i;
        return &i;
    }
};

class CScriptConsoleError : public CScriptFunction {
public:
    virtual bool Call(CScriptStack *stack) {
        if (stack->IsEmpty()) return false;
        CScriptObject *val = stack->Pop();
        LogErrorStr(val->AsString()); val->Drop();
        return true;
    }
    virtual CScriptObject *Instance() {
        static CScriptConsoleError i;
        return &i;
    }
};

class CScriptConsole : public CScriptObject {
public:
    CScriptConsole() {
        Register("log", CScriptConsoleLog::Instance());
        Register("error", CScriptConsoleError::Instance());
    }

    virtual CScriptObject *Instance() {
        static CScriptConsole i;
        return &i;
    }
};

class CScriptModule : public CScriptObject {
public:
    std::string name;

    CScriptModule() {}
    CScriptModule(const CByteArray &memory) {
        FromMemory(memory);
    }
    virtual ~CScriptModule() {
        if (HasInstance(this)) SetInstance(name, nullptr);
    }

    static CScriptModule *GlobalSpace() {
        static CScriptModule module; static bool initialized = false;
        if (!initialized) {
            SetInstance("stdlib", &module);

            module.Register("console", CScriptConsole::Instance());
            initialized = true;
        }
        return &module;
    }
    static CScriptModule *SetInstance(const std::string &name, CScriptModule *module);
    static CScriptModule *GetInstance(const std::string &name);
    static bool HasInstance(CScriptModule *module);

    CScriptObject *Instance() { 
        CScriptModule *inst = GetInstance(name); 
        if (!inst) {
            SetInstance(name, this);
            return Grab();
        }
        return inst;
    }

    CByteArray ToMemory() const;
    bool FromMemory(const CByteArray &memory);
};

#endif