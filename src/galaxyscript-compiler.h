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


class CScriptCompiler {

};

#endif