// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <chainparams.h>
#include <codecvt>
#include <fs.h>
#include <fstream>
#include <galaxycash.h>
#include <galaxyscript.h>
#include <galaxyscript-compiler.h>
#include <hash.h>
#include <locale>
#include <memory>
#include <pow.h>
#include <stack>
#include <stdint.h>
#include <string>
#include <tinyformat.h>
#include <uint256.h>
#include <util.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>


static std::string g_keywords[] = {
    "var",
    "let",
    "const",
    "new",
    "delete",
    "void",
    "null",
    "true",
    "false",
    "undefined",
    "typeof",
    "instanceof",
    "in",
    "number",
    "string",
    "function",
    "array",
    "object",
    "if",
    "else",
    "for",
    "while",
    "do",
    "break",
    "continue",
    "return",
    "async",
    "await",
    "with",
    "switch",
    "case",
    "default",
    "this",
    "super",
    "try",
    "throw",
    "catch",
    "finally",
    "debugger",
    "class",
    "enum",
    "extends",
    "implements",
    "interface",
    "package",
    "private",
    "protected",
    "static",
    "import",
    "export",
    "yield",
    "native",
    "buildin",
    "constructor",
    "destructor"};

static const uint32_t g_keywords_flags[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    CScriptToken::Native,
    CScriptToken::Buildin,
    0,
    0};

static const std::string g_operators[] = {
    ">>>=", "<<=", ">>=", ">>>", "!==", "===", "!=", "%=", "&&",
    "&=", "*=", "*", "++", "+=", "--", "-=", "<<", "<=", "==", ">=", ">>",
    "^=", "|=", "||", "!", "%", "&", "+", "-", "=",
    ">", "<", "^", "|", "~"};

static const uint32_t g_operators_flags[] = {
    CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Binary, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Unary, CScriptToken::Binary | CScriptToken::Logical,
    CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Binary, CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Binary, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary,
    CScriptToken::Unary, CScriptToken::Unary, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Unary, CScriptToken::Binary, CScriptToken::Binary, CScriptToken::Binary, CScriptToken::Binary, CScriptToken::Unary,
    CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary | CScriptToken::Logical, CScriptToken::Binary, CScriptToken::Binary, CScriptToken::Binary};


static const std::string g_punctuations[] = {
    ".", ",", ";", ":", "[", "]", "{", "}", "(", ")"};

static const uint32_t g_punctuations_flags[] = {
    0, 0, 0, 0, 0, 0, 0, 0};


CScriptLexer::CScriptLexer() : pos(0), line(0)
{
}
CScriptLexer::CScriptLexer(const std::string& file, const std::string& code) : buffer(code), file(file), pos(0), line(0)
{
}
CScriptLexer::~CScriptLexer()
{
}

bool CScriptLexer::Eof() const
{
    if (buffer.empty()) return true;
    return pos >= buffer.length();
}

char CScriptLexer::LastChar()
{
    if (pos < buffer.length()) {
        return *(buffer.c_str() + pos);
    }
    return 0;
}

char CScriptLexer::PrevChar()
{
    if (buffer.length() > 0 && pos >= 0) {
        if (pos == 0) return *buffer.c_str();
        return *(buffer.c_str() + (pos - 1));
    }
    return 0;
}

char CScriptLexer::NextChar()
{
    if (!Eof()) {
        if (buffer.length() <= (pos + 1)) return 0;
        return *(buffer.c_str() + (pos + 1));
    }
    return 0;
}

char CScriptLexer::Advance()
{
    if (!Eof()) {
        pos++;
        if (!Eof())
            return *(buffer.c_str() + pos);
        return 0;
    }
    return 0;
}

bool IsWhitespace(int c)
{
    if (c == ' ')
        return true;
    else if (c == '\t')
        return true;
    return false;
}

bool IsEndline(int c)
{
    if (c == '\n')
        return true;
    else if (c == '\r')
        return true;
    else if (c == ';')
        return true;
    return false;
}

void CScriptLexer::SkipWhitespace()
{
    while (!Eof() && IsWhitespace(LastChar())) {
        pos++;
    }
    cur.pos = pos;

    if (LastChar() == '/' && NextChar() == '/') {
        pos += 2;

        while (LastChar() != '\n' && LastChar() != '\r' && !Eof())
            pos++;

        cur.pos = pos;
    }

    if (LastChar() == '/' && NextChar() == '*') {
        pos += 2;

        while (LastChar() != '*' && NextChar() != '/' && !Eof())
            pos++;

        cur.pos = pos;
    }
}

bool CScriptLexer::ReadString(std::string& tok)
{
    if (Eof()) return false;
    const char* p = buffer.c_str() + pos;
    if (*p == '"') {
        tok.clear();
        p++;
        pos++;
        while (!Eof() && *p != '"') {
            tok += *p;
            p++;
            pos++;
        }
        if (!Eof() && *p == '"') {
            pos++;
        }
        return !tok.empty();
    }
    if (*p == '\'') {
        tok.clear();
        p++;
        pos++;
        while (!Eof() && *p != '\'') {
            tok += *p;
            p++;
            pos++;
        }
        if (!Eof() && *p == '\'') {
            pos++;
        }
        return !tok.empty();
    }
    return false;
}

bool CScriptLexer::ReadNumber(std::string& tok, uint32_t& flags)
{
    if (Eof()) return false;
    const char* p = buffer.c_str() + pos;
    if (isdigit(*p)) {
        tok.clear();
        tok += *p;
        p++;
        pos++;
        while (!Eof() && (isdigit(*p) || *p == '.')) {
            if (*p == '.')
                flags |= CScriptToken::Float;
            tok += *p;
            p++;
            pos++;
        }
        flags |= CScriptToken::Literal;
        return !tok.empty();
    }
    if (*p == '.') {
        p++;
        pos++;
        if (p && isdigit(*p)) {
            tok = '.';
            flags |= CScriptToken::Float;

            while (!Eof() && isdigit(*p)) {
                tok += *p;
                p++;
                pos++;
            }

            if (!tok.empty()) {
                return true;
            } else {
                pos--;
                return false;
            }
        } else {
            pos--;
        }
    }

    if (*p == '-') {
        p++;
        pos++;
        if (p && isdigit(*p)) {
            tok = '-';
            flags |= CScriptToken::Negative;

            while (!Eof() && (isdigit(*p) || *p == '.')) {
                if (*p == '.')
                    flags |= CScriptToken::Float;
                tok += *p;
                p++;
                pos++;
            }

            if (!tok.empty()) {
                return true;
            } else {
                pos--;
                return false;
            }
        } else {
            pos--;
        }
    }

    if (*p == 'u') {
        p++;
        pos++;
        if (p && isdigit(*p)) {
            tok.clear();
            flags |= CScriptToken::Unsigned;

            while (!Eof() && isdigit(*p)) {
                tok += *p;
                p++;
                pos++;
            }

            if (!tok.empty()) {
                return true;
            } else {
                pos--;
                return false;
            }
        } else {
            pos--;
        }
    }

    return false;
}

bool Match(const char* source, const char* value)
{
    if (!source || *source == '\0' || !value || *value == '\0') return false;
    while (source && value) {
        if (*value == '\0') return true;
        if (*source == '\0') return false;
        if (*source != *value)
            return false;
        else {
            source++;
            value++;
        }
    }
    return false;
}

bool IsKeyword(const char* source, std::string* value = 0, uint32_t* flags = 0)
{
    for (size_t i = 0; i < sizeof(g_keywords) / sizeof(g_keywords[0]); i++) {
        if (Match(source, g_keywords[i].c_str())) {
            if (value) *value = g_keywords[i];
            if (flags) *flags |= g_keywords_flags[i];
            return true;
        }
    }
    return false;
}

bool IsOperator(const char* source, std::string* value = 0, uint32_t* flags = 0)
{
    for (size_t i = 0; i < sizeof(g_operators) / sizeof(g_operators[0]); i++) {
        if (Match(source, g_operators[i].c_str())) {
            if (value) *value = g_operators[i];
            if (flags) *flags |= g_operators_flags[i];
            return true;
        }
    }
    return false;
}

bool IsPunctuation(const char* source, std::string* value = 0, uint32_t* flags = 0)
{
    for (size_t i = 0; i < sizeof(g_punctuations) / sizeof(g_punctuations[0]); i++) {
        if (Match(source, g_punctuations[i].c_str())) {
            if (value) *value = g_punctuations[i];
            if (flags) *flags |= g_punctuations_flags[i];
            return true;
        }
    }
    return false;
}

bool CScriptLexer::ReadToken(CScriptToken& tok)
{
    CScriptToken lst(cur);

    cur = CScriptToken();
    cur.prv = new CScriptToken(lst);
    cur.pos = pos;
    cur.file = file;
    cur.line = line;

    SkipWhitespace();

    if (Eof()) return false;

    if (IsEndline(LastChar())) {
        cur.file = file;
        cur.line = line;
        line++;
        cur.pos = pos;
        pos++;
        cur.type = CScriptToken::EndOfline;
        cur.flags = CScriptToken::None;
        cur.value = "\n";
        tok = cur;
        return true;
    }


    if (ReadString(cur.value)) {
        cur.type = CScriptToken::String;
        cur.flags = CScriptToken::Literal;
        tok = cur;
        return true;
    }

    if (ReadNumber(cur.value, cur.flags)) {
        cur.type = CScriptToken::Number;
        tok = cur;
        return true;
    }

    const char* p = buffer.c_str() + pos;

    if (Match(p, "true")) {
        cur.file = file;
        cur.line = line;
        cur.pos = pos;
        cur.type = CScriptToken::Boolean;
        cur.flags = CScriptToken::True;
        cur.value = "true";
        pos += 4;
        tok = cur;
        return true;
    }

    if (Match(p, "false")) {
        cur.file = file;
        cur.line = line;
        cur.pos = pos;
        cur.type = CScriptToken::Boolean;
        cur.flags = 0;
        cur.value = "false";
        pos += 5;
        tok = cur;
        return true;
    }

    for (size_t i = 0; i < sizeof(g_operators) / sizeof(g_operators[0]); i++) {
        if (Match(p, g_operators[i].c_str())) {
            cur.file = file;
            cur.line = line;
            cur.pos = pos;
            cur.type = CScriptToken::Operator;
            cur.flags = g_operators_flags[i];
            cur.value = g_operators[i];
            pos += g_operators[i].length();
            tok = cur;
            return true;
        }
    }

    for (size_t i = 0; i < sizeof(g_punctuations) / sizeof(g_punctuations[0]); i++) {
        if (Match(p, g_punctuations[i].c_str())) {
            cur.file = file;
            cur.line = line;
            cur.pos = pos;
            cur.type = CScriptToken::Punctuation;
            cur.flags = g_punctuations_flags[i];
            cur.value = g_punctuations[i];
            pos += g_punctuations[i].length();
            tok = cur;
            return true;
        }
    }

    for (size_t i = 0; i < sizeof(g_keywords) / sizeof(g_keywords[0]); i++) {
        if (Match(p, g_keywords[i].c_str())) {
            cur.file = file;
            cur.line = line;
            cur.pos = pos;
            cur.type = CScriptToken::Keyword;
            cur.flags = g_keywords_flags[i];
            cur.value = g_keywords[i];
            pos += g_keywords[i].length();
            tok = cur;
            return true;
        }
    }

    cur.type = CScriptToken::Identifier;
    cur.flags = 0;

    while (!Eof() && p && !IsWhitespace(*p) && !IsEndline(*p) && *p != '\'' && *p != '"') {
        if (IsPunctuation(p)) break;
        if (IsOperator(p)) break;
        cur.value += *p;
        p++;
        pos++;
    }

    if (!cur.value.empty()) {
        tok = cur;
        return true;
    }


    UnreadToken(lst);
    return false;
}

void CScriptLexer::SkipToken()
{
    CScriptToken tok;
    ReadToken(tok);
}

void CScriptLexer::UnreadToken(const CScriptToken& tok)
{
    pos = tok.pos;
    line = tok.line;
    file = tok.file;
    cur = tok;
}

bool CScriptLexer::CheckToken(const std::string& val)
{
    CScriptToken tok;
    if (!ReadToken(tok)) return false;
    if (val != tok.value) {
        UnreadToken(tok);
        return false;
    }

    UnreadToken(tok);
    return true;
}

bool CScriptLexer::CheckType(const uint8_t type)
{
    CScriptToken tok;
    if (!ReadToken(tok)) return false;
    if (type != tok.type) {
        UnreadToken(tok);
        return false;
    }

    UnreadToken(tok);
    return true;
}

bool CScriptLexer::MatchToken(const std::string& val)
{
    CScriptToken tok;
    if (!ReadToken(tok)) return false;
    if (val != tok.value) {
        UnreadToken(tok);
        return false;
    }

    return true;
}

bool CScriptLexer::MatchType(const uint8_t type)
{
    CScriptToken tok;
    if (!ReadToken(tok)) return false;
    if (type != tok.type) {
        UnreadToken(tok);
        return false;
    }

    return true;
}