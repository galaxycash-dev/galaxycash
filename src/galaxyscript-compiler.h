// Copyright (c) 2017-2019 The GalaxyCash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef GALAXYCASH_EXT_SCRIPT_COMPILER_H
#define GALAXYCASH_EXT_SCRIPT_COMPILER_H

class CScriptError {
public:

    enum {
        Unknown = 0,
        Warning,
        NotFound,
        BadSymbol,
        BadName,
        BadLiteral,
        BadString,
        Missings
    };
    int code;
    std::string file;
    size_t line;
    std::string text;

    CScriptError() : code(-1), line(0) {}
    CScriptError(const CScriptError& err) : code(err.code), file(err.file), line(err.line), text(err.text) {}
    CScriptError(const int code, const std::string& file, const size_t line, const std::string& text) : code(code), file(file), line(line), text(text) {}

    bool IsError() const { return (code > Warning); }
};

class CScriptToken
{
public:
    enum {
        Unknown = 0,
        Number,
        Boolean,
        String,
        Keyword,
        Operator,
        Punctuation,
        Identifier,
        EndOfline
    };

    enum {
        None = 0,
        Literal = (1 << 0),
        Float = (1 << 1),
        Unary = (1 << 2),
        Binary = (1 << 3),
        Unsigned = (1 << 4),
        Logical = (1 << 5),
        Hex = (1 << 6),
        Big = (1 << 7),
        Negative = (1 << 8),
        Assignment = (1 << 9),
        Native = (1 << 10),
        Buildin = (1 << 11),
        True = (1 << 12)
    };

    CScriptToken* prv;
    uint8_t type;
    uint32_t flags;
    std::string value;
    std::string file;
    size_t pos, line;

    CScriptToken() : prv(nullptr), type(Unknown), flags(None), pos(0), line(0) {}
    CScriptToken(const CScriptToken& tok) : prv(nullptr), type(tok.type), flags(tok.flags), pos(tok.pos), line(tok.line)
    {
        if (tok.prv)
            this->prv = new CScriptToken(*tok.prv);
    }
    ~CScriptToken()
    {
        if (prv) delete prv;
    }

    CScriptToken& operator=(const CScriptToken& tok)
    {
        if (prv) delete prv;
        prv = nullptr;
        if (tok.prv) prv = new CScriptToken(*tok.prv);
        type = tok.type;
        flags = tok.flags;
        value = tok.value;
        file = tok.file;
        pos = tok.pos;
        line = tok.line;
        return *this;
    }

    bool IsNull() const
    {
        return type == Unknown && flags == None;
    }

    void SetNull()
    {
        if (prv) delete prv;
        prv = nullptr;
        type = Unknown;
        flags = None;
        value.clear();
        file.clear();
        pos = 0;
        line = 0;
    }

    bool IsBoolean() const
    {
        return (type == Boolean);
    }
    bool IsTrue() const {
        return IsBoolean() && (value == "true");
    }
    bool IsString() const {
        return (type == String);
    }
    bool IsNumber() const
    {
        return (type == Number);
    }
    bool IsFloat() const
    {
        return IsNumber() && (flags & Float);
    }
    bool IsUnsigned() const
    {
        return IsNumber() && (flags & Unsigned);
    }
    bool IsHexNum() const
    {
        return IsNumber() && (flags & Hex);
    }
    bool IsBigNum() const
    {
        return IsNumber() && (flags & Big);
    }
    bool IsNegative() const
    {
        return IsNumber() && (flags & Negative);
    }

    bool IsOperator() const
    {
        return (type == Operator);
    }
    bool IsUnary() const
    {
        return (flags & Unary);
    }
    bool IsBinary() const
    {
        return (flags & Binary);
    }
    bool IsLogical() const
    {
        return (flags & Logical);
    }

    bool IsNative() const
    {
        return (flags & Native);
    }
    bool IsBuildin() const
    {
        return (flags & Buildin);
    }
    bool IsLiteral() const
    {
        return (flags & Literal);
    }
    bool IsVariableDeclare() const
    {
        return (type == Keyword) && (value == "var" || value == "const" || value == "static");
    }
    bool IsFunctionDeclare() const
    {
        return (type == Keyword) && (value == "function");
    }
    bool IsClassDeclare() const
    {
        return (type == Keyword) && (value == "class");
    }
    bool IsConstructorDeclare() const
    {
        return (type == Keyword) && (value == "constructor");
    }
    bool IsDestructorDeclare() const
    {
        return (type == Keyword) && (value == "destructor");
    }

    bool operator<(const CScriptToken& tok) const { return (type < tok.type) || (value < tok.value); }
    bool operator==(const CScriptToken& tok) const { return (type == tok.type) && (value == tok.value); }
};

class CScriptLexer
{
public:
    CScriptToken cur;
    std::string buffer, file;
    size_t pos, line;
    std::vector<std::string> errs;

    CScriptLexer();
    CScriptLexer(const std::string& file, const std::string& code);
    virtual ~CScriptLexer();

    bool Eof() const;

    char PrevChar();
    char LastChar();
    char NextChar();
    char Advance();
    void SkipWhitespace();


    bool ReadToken(CScriptToken& tok);
    bool ReadString(std::string& str);
    bool ReadNumber(std::string& str, uint32_t& flags);
    void UnreadToken(const CScriptToken& tok);
    bool MatchToken(const std::string& val);
    bool MatchType(const uint8_t type);
    bool CheckToken(const std::string& val);
    bool CheckType(const uint8_t type);
    void SkipToken();
};

class CScriptAssembler {
public:
    CByteArray code;

    CScriptAssembler() {}
    CScriptAssembler(const CScriptAssembler &as) : code(as.code) {}
    CScriptAssembler(const CByteArray &code) : code(code) {}

    CScriptAssembler &Opcode(const uint8_t op) { code.push_back(op); return *this; }

    CScriptAssembler &Emit(const int8_t value) {
        code.push_back(*(uint8_t*) &value);
        return *this;
    }
    CScriptAssembler &Emit(const uint8_t value) {
        code.push_back(value);
        return *this;
    }

    CScriptAssembler &Emit(const int16_t &value) {
        const int16_t v = htole16(value);
        code.push_back(*(((uint8_t*) &v) + 0));
        code.push_back(*(((uint8_t*) &v) + 1));
        return *this;
    }
    CScriptAssembler &Emit(const uint16_t value) {
        const uint16_t v = htole16(value);
        code.push_back(*(((uint8_t*) &v) + 0));
        code.push_back(*(((uint8_t*) &v) + 1));
        return *this;
    }

    CScriptAssembler &Emit(const int32_t &value) {
        const int32_t v = htole32(value);
        code.push_back(*(((uint8_t*) &v) + 0));
        code.push_back(*(((uint8_t*) &v) + 1));
        code.push_back(*(((uint8_t*) &v) + 2));
        code.push_back(*(((uint8_t*) &v) + 3));
        return *this;
    }
    CScriptAssembler &Emit(const uint32_t value) {
        const uint32_t v = htole32(value);
        code.push_back(*(((uint8_t*) &v) + 0));
        code.push_back(*(((uint8_t*) &v) + 1));
        code.push_back(*(((uint8_t*) &v) + 2));
        code.push_back(*(((uint8_t*) &v) + 3));
        return *this;
    }

    CScriptAssembler &Emit(const int64_t &value) {
        const int64_t v = htole64(value);
        code.push_back(*(((uint8_t*) &v) + 0));
        code.push_back(*(((uint8_t*) &v) + 1));
        code.push_back(*(((uint8_t*) &v) + 2));
        code.push_back(*(((uint8_t*) &v) + 3));
        code.push_back(*(((uint8_t*) &v) + 4));
        code.push_back(*(((uint8_t*) &v) + 5));
        code.push_back(*(((uint8_t*) &v) + 6));
        code.push_back(*(((uint8_t*) &v) + 7));
        return *this;
    }
    CScriptAssembler &Emit(const uint64_t value) {
        const uint64_t v = htole64(value);
        code.push_back(*(((uint8_t*) &v) + 0));
        code.push_back(*(((uint8_t*) &v) + 1));
        code.push_back(*(((uint8_t*) &v) + 2));
        code.push_back(*(((uint8_t*) &v) + 3));
        code.push_back(*(((uint8_t*) &v) + 4));
        code.push_back(*(((uint8_t*) &v) + 5));
        code.push_back(*(((uint8_t*) &v) + 6));
        code.push_back(*(((uint8_t*) &v) + 7));
        return *this;
    }
    CScriptAssembler &Emit(const std::string &value) {
        Emit((uint32_t) value.length());
        for (size_t i = 0; i < value.length(); i++) Emit(value[i]);
        return *this;
    }
    CScriptAssembler &Emit(const CByteArray &value) {
        Emit((uint32_t) value.size());
        for (size_t i = 0; i < value.size(); i++) Emit(value[i]);
        return *this;
    }
    CScriptAssembler &Emit(const bool value) {
        return Emit((uint8_t) (value ? 1 : 0));
    }
    CScriptAssembler &Emit(const uint160 &x) {
        Emit(x.size());
        for (size_t i = 0; i < x.size(); i++) Emit(x.begin()[i]);
        return *this;
    }
    CScriptAssembler &Emit(const uint256 &x) {
        Emit(x.size());
        for (size_t i = 0; i < x.size(); i++) Emit(x.begin()[i]);
        return *this;
    }
    CScriptAssembler &Emit(const uint512 &x) {
        Emit(x.size());
        for (size_t i = 0; i < x.size(); i++) Emit(x.begin()[i]);
        return *this;
    }

    CScriptAssembler &Nop() { return Opcode(CScriptOpcode::NOP); }
    CScriptAssembler &Pop() { return Opcode(CScriptOpcode::POP); }
    CScriptAssembler &Dup() { return Opcode(CScriptOpcode::DUP); }
    CScriptAssembler &Ret() { return Opcode(CScriptOpcode::RET); }
    CScriptAssembler &End() { return Opcode(CScriptOpcode::END); }

    CScriptAssembler &Declare(const std::string &name, const uint8_t type, const uint8_t enumerable) { 
        Opcode(CScriptOpcode::DECLARE); 
        Emit(name); 
        Emit(type); 
        return Emit(enumerable); 
    }
                
};

class CScriptNode {
public:
    virtual ~CScriptNode() {}
    virtual std::string Type() const { return "None"; }

    virtual bool Codegen(CScriptAssembler &as) { 
        as.Nop();
        return false;
    }
};

class CScriptBlockNode : public CScriptNode {
public: 
    std::vector<CScriptNode*> nodes;

    CScriptBlockNode() {}
    CScriptBlockNode(const std::vector<CScriptNode*> &nodes) : nodes(nodes) {}
    virtual ~CScriptBlockNode() {
        for (size_t i = 0; i < nodes.size(); i++) delete nodes[i];
    }
    virtual std::string Type() const { return "Block"; }

    virtual bool Codegen(CScriptAssembler &as) { 
        as.Block();
        for (size_t i = 0; i < nodes.size(); i++) {
            if (!nodes[i]->Codegen(as)) return false;
        }
        as.End();
        return true;
    }
};

class CScriptDeclareNode : public CScriptNode {
public:
    uint8_t type, enumerable;
    std::string name;

    CScriptDeclareNode() {}
    CScriptDeclareNode(const std::string &name, const uint8_t type, const uint8_t enumerable) : name(name), type(type), enumerable(enumerable) {}

    virtual std::string Type() const { return "Declare"; }

    virtual bool Codegen(CScriptAssembler &as) { 
        if (!as.Declare(name, type, enumerable)) return false;
        return true;
    }
};

class CScriptBinaryNode : public CScriptNode {
public:
    CScriptNode *left, *right;

    CScriptBinaryNode(CScriptNode *left, CScriptNode *right) : left(left), right(right) {}
    virtual ~CScriptBinaryNode() {
        if (left) delete left;
        if (right) delete right;
    }

    virtual CScriptNode *Left() { return left; }
    virtual CScriptNode *Right() { return right; }

    virtual std::string Type() const { return "Binary"; }

    
    virtual bool Codegen(CScriptAssembler &as) { 
        if (!left->Codegen(as)) return false;
        if (!right->Codegen(as)) return false;
        return true;
    }
};

class CScriptCompiler {

};

#endif