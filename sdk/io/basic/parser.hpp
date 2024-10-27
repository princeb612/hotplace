/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_PARSER__
#define __HOTPLACE_SDK_IO_BASIC_PARSER__

#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/pattern/aho_corasick.hpp>
#include <sdk/base/pattern/trie.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {
namespace io {

enum token_t {
    token_unknown = 0,
    token_alpha = 1,       // [a-zA-Z]
    token_number = 2,      // [0-9]
    token_space = 3,       // whitespace
    token_lparen = 4,      // (parentheses)
    token_rparen = 5,      // (parentheses)
    token_lbracket = 6,    // [brackets]
    token_rbracket = 7,    // [brackets]
    token_lbrace = 8,      // {braces}
    token_rbrace = 9,      // {braces}
    token_squote = 10,     // '
    token_dquote = 11,     // "
    token_greater = 12,    // >
    token_lesser = 13,     // <
    token_equal = 14,      // =
    token_plus = 15,       // +
    token_minus = 16,      // -
    token_multi = 17,      // *
    token_divide = 18,     // /
    token_colon = 19,      // :
    token_semicolon = 20,  // ;
    token_comma = 21,      // ,
    token_dot = 22,        // .
    token_newline = 23,    // \n
    token_and = 24,
    token_or = 25,

    token_identifier = 32,   // [a-zA-Z0-9].*
    token_quot_string = 33,  // \"[a-zA-Z0-9].*\"
    token_comments = 34,     // parser::token.comments .... until the newline
    token_assign = 35,
    token_lvalue = 36,
    token_emphasis = 37,
    token_type = 38,
    token_class = 39,
    token_tag = 40,

    // ASN.1
    token_bool,
    token_int,
    token_bitstring,
    token_octstring,
    token_null,
    token_oid,
    token_objdesc,
    token_extern,
    token_real,
    token_enum,
    token_embedpdv,
    token_utf8string,
    token_reloid,
    token_sequence,
    token_sequenceof,
    token_set,
    token_setof,
    token_numstring,
    token_printstring,
    token_t61string,  // teletexstring
    token_videotexstring,
    token_ia5string,
    token_utctime,
    token_generalizedtime,
    token_graphicstring,
    token_visiblestring,  // iso64string
    token_genaralstring,
    token_universalstring,
    token_bmpstring,
    token_date,
    token_timeofday,
    token_datetime,
    token_duration,

    token_true,
    token_false,

    token_universal,
    token_application,
    token_private,

    token_implicit,
    token_explicit,

    token_builtintype,
    token_taggedmode,

    // reserved
    token_char,
    token_usertype,
};

struct token_description {
    uint32 index;
    uint32 type;
    uint32 tag;
    size_t pos;
    size_t size;
    size_t line;
    const char* p;
};

/**
 * @brief   parse
 * @sample
 *          constexpr char asn1_structure[] =
 *              R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
 *                  name Name,
 *                  title [0] VisibleString,
 *                  number EmployeeNumber,
 *                  dateOfHire [1] Date,
 *                  nameOfSpouse [2] Name,
 *                  children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {} }
 *              ChildInformation ::= SET { name Name, dateOfBirth [0] Date}
 *              Name ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString}
 *              EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
 *              Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)";
 *
 *          constexpr char pattern[] = "[APPLICATION 2] IMPLICIT INTEGER";
 *
 *          parser p;
 *          p.add_token("::=", token_assign).add_token("--", token_comments);
 *          parser::context context1;
 *          p.parse(context1, asn1_structure, strlen(asn1_structure));
 *
 *          auto dump_handler = [&](const token_description* desc) -> void {
 *              _logger->writeln("line %zi type %d(%s) index %d pos %zi len %zi (%.*s)",
 *                  desc->line, desc->type, p.typeof_token(desc->type).c_str(),
 *                  desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
 *          };
 *          context1.for_each(dump_handler);
 */
class parser {
   public:
    enum parser_flag_t {
        parse_lookup_readonly = 1,  // see parser::context::parse
    };
    struct search_result {
        bool match;
        const char* p;
        size_t size;
        size_t pos;
        int begidx;
        int endidx;

        search_result() : match(false), p(nullptr), size(0), pos(-1), begidx(-1), endidx(-1) {}
    };

    /**
     * @brief   parser::token
     * @sa      parser::parse
     */
    class token {
       public:
        token();
        token(const token& rhs);

        token& init();
        token& increase();
        token& set_type(uint32 type);
        token& set_tag(uint32 tag);
        token& update_pos(size_t pos);
        token& update_size(size_t size);
        token& newline();

        token& set_index(uint32 idx);
        uint32 get_index() const;
        uint32 get_type() const;
        uint32 get_tag() const;
        size_t get_pos() const;
        size_t get_size() const;
        size_t get_line() const;
        bool empty();
        size_t size();

        std::string as_string(const char* p);
        void visit(const char* p, std::function<void(const token* t)> f) const;

        parser::token* clone();

       private:
        uint32 _type;
        uint32 _tag;
        size_t _pos;
        size_t _size;
        size_t _line;
        uint32 _index;  // 0 reserved, start with 1
    };

    class context {
       public:
        context();
        ~context();

        return_t parse(parser* obj, const char* p, size_t size, uint32 flags = 0);

        /**
         * @brief   character-level search
         */
        search_result csearch(parser* obj, const char* pattern, size_t size_pattern, unsigned int pos = 0) const;
        search_result csearch(parser* obj, const std::string& pattern, unsigned int pos = 0) const;
        search_result csearch(parser* obj, const basic_stream& pattern, unsigned int pos = 0) const;

        /**
         * @brief   word-level search
         */
        search_result wsearch(parser* obj, const context& pattern, unsigned int pos = 0) const;
        search_result wsearch(parser* obj, const char* pattern, size_t size_pattern, unsigned int pos = 0) const;
        search_result wsearch(parser* obj, const std::string& pattern, unsigned int pos = 0) const;
        search_result wsearch(parser* obj, const basic_stream& pattern, unsigned int pos = 0) const;
        /**
         * @brief   word-level comparison
         */
        bool compare(parser* obj, const parser::context& rhs) const;

        /**
         * @brief   pattern-level search
         */
        void add_pattern(parser* obj);
        std::multimap<range_t, unsigned> psearch(parser* obj) const;
        std::multimap<range_t, unsigned> psearchex(parser* obj) const;

        void clear();

        void for_each(std::function<void(const token_description* desc)> f) const;
        void for_each(const search_result& res, std::function<void(const token_description* desc)> f) const;
        void walk(std::function<void(const char* p, const parser::token*)> f);

        void wsearch_result(search_result& result, uint32 idx, size_t size) const;
        /**
         * @brief   search_result
         * @sample
         *          result = p.psearch(context);
         *          for (auto [range, pid] : result) {
         *              parser::search_result res;
         *              context.psearch_result(res, range, pid);
         *              _logger->writeln("pos [%i..%i] pattern[%i] %.*s", res.begidx, res.endidx, (unsigned)res.size, res.p);
         *          }
         */
        void psearch_result(search_result& result, range_t range) const;

        return_t get(uint32 index, token_description* desc);

       protected:
        return_t init(parser* obj, const char* p, size_t size);
        return_t add_context_token(std::function<bool(int, parser::token*)> hook = nullptr);
        parser::token& get_token();
        parser::token* last_token();

       private:
        parser* _parser;
        const char* _p;
        size_t _size;
        parser::token _token;
        std::vector<parser::token*> _tokens;
    };

   public:
    parser();
    ~parser();

    /*
     * @brief   parse
     * @param   parser::context& context [out]
     * @param   const char* p [in]
     * @param   size_t size [in]
     * @remarks
     */
    return_t parse(parser::context& context, const char* p, size_t size);
    return_t parse(parser::context& context, const char* p);
    return_t parse(parser::context& context, const std::string& p);
    return_t parse(parser::context& context, const basic_stream& p);
    /**
     * @brief   pattern search (character-level)
     * @param
     * @sample
     *          // strlen(asn1_structure) --> 612, strlen(pattern) --> 32
     *          // character search - KMP N(asn1_structure)=612, M(pattern)=32, O(612+32)
     *          // asn1_sequence 612 bytes
     *          // pattern        32 bytes
     *          parser::search_result cresult = p.csearch(context1, pattern, 0);
     *          parser::search_result cresult2 = p.csearch(context1, pattern2, strlen(pattern2), cresult.pos);
     */
    search_result csearch(const parser::context& context, const char* pattern, size_t size_pattern, unsigned int pos = 0);
    search_result csearch(const parser::context& context, const std::string& pattern, unsigned int pos = 0);
    search_result csearch(const parser::context& context, const basic_stream& pattern, unsigned int pos = 0);
    /**
     * @brief   pattern search (word-level)
     * @param   const parser::context& context [in]
     * @param   const char* pattern [in]
     * @param   size_t size_pattern [in]
     * @param   unsigned int pos [inopt]
     * @sample
     *          // context1._tokens.size() --> 93, pattern._tokens.size() --> 6
     *          // word search - KMP N(context1)=93, M(pattern)=6, O(93+6)
     *          // asn1_structure 93 tokens [1 2 3 4 ... 3 4 21 6 7 33 ... 7 4 -1]
     *          // pattern         6 tokens [            3 4 21 6 7 33           ]
     *          parser::search_result wresult = p.wsearch(context1, pattern, 0);
     *          parser::search_result wresult2 = p.wsearch(context1, pattern2, strlen(pattern2), wresult.endidx + 1);
     */
    search_result wsearch(const parser::context& context, const char* pattern, size_t size_pattern, unsigned int pos = 0);
    search_result wsearch(const parser::context& context, const std::string& pattern, unsigned int pos = 0);
    search_result wsearch(const parser::context& context, const basic_stream& pattern, unsigned int pos = 0);
    /**
     * @brief   compare (word-level comparison, ignore white spaces)
     * @param   const char* lhs [in]
     * @param   const char* rhs [in]
     * @sample
     *          constexpr char data1[] = "[APPLICATION 2] IMPLICIT INTEGER";
     *          constexpr char data2[] = "[APPLICATION  2]  IMPLICIT  INTEGER";
     *          bool test = p.compare(data1, data2); // true
     */
    static bool compare(parser* obj, const char* lhs, const char* rhs);
    bool compare(const char* lhs, const char* rhs);
    bool compare(const parser::context& lhs, const parser::context& rhs);

    /**
     * @brief   multiple pattern search
     * @sa      t_aho_corasick / t_aho_corasick
     * @sample
     *          // sketch
     *          constexpr char sample[] = R"(int a; int b = 0; bool b = true;)";
     *          p.add_token("bool", 0x1000).add_token("int", 0x1001).add_token("true", 0x1002).add_token("false", 0x1002);
     *          p.parse(context, sample);
     *          p.add_pattern("int a;").add_pattern("int a = 0;").add_pattern("bool a;").add_pattern("bool a = true;");
     =          result = p.psearch();
     *          // std::multimap<unsigned, size_t> expect = {{0, 0}, {1, 3}, {3, 8}};
     *          // sample  : int a; int b = 0; bool b = true;
     *          // pattern : 0      1          3
     *          // tokens  : 0   12 3   4 5 67 8    9 a b   c
     */
    parser& add_pattern(const char* p, size_t size);
    parser& add_pattern(const std::string& pattern);
    /**
     * @brief   pattern search (pattern-level)
     * @remarks
     *          // sketch
     *
     *          // define token_builtintype, token_taggedmode, token_of, token_default
     *
     *          p.add_token("::=", token_assign)
     *              .add_token("--", token_comments)
     *              .add_token("BOOLEAN", token_builtintype, token_bool)                 // BooleanType
     *              .add_token("INTEGER", token_builtintype, token_int)                  // IntegerType
     *              .add_token("BIT STRING", token_builtintype, token_bitstring)         // BitStringType
     *              .add_token("OCT STRING", token_builtintype, token_octstring)         // BitStringType
     *              .add_token("NULL", token_builtintype, token_null)                    // NullType
     *              .add_token("REAL", token_builtintype, token_real)                    // RealType
     *              .add_token("IA5String", token_builtintype, token_ia5string)          // CharacterStringType
     *              .add_token("VisibleString", token_builtintype, token_visiblestring)  // CharacterStringType
     *              .add_token("SEQUENCE", token_sequence)
     *              .add_token("SEQUENCE OF", token_sequenceof)
     *              .add_token("SET", token_set)
     *              .add_token("SET OF", token_setof)
     *              // BooleanValue ::= TRUE | FALSE
     *              .add_token("TRUE", token_bool, token_true)
     *              .add_token("FALSE", token_bool, token_false)
     *              // Class ::= UNIVERSAL | APPLICATION | PRIVATE | empty
     *              .add_token("UNIVERSAL", token_class, token_universal)
     *              .add_token("APPLICATION", token_class, token_application)
     *              .add_token("PRIVATE", token_class, token_private)
     *              // TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
     *              .add_token("IMPLICIT", token_taggedmode, token_implicit)
     *              .add_token("EXPLICIT", token_taggedmode, token_explicit);
     *
     *          p.add_token("$pattern_builtintype", token_builtintype)
     *              .add_token("$pattern_usertype", token_usertype)
     *              .add_token("$pattern_class", token_class)
     *              .add_token("$pattern_sequence", token_sequence)
     *              .add_token("$pattern_sequenceof", token_sequenceof)
     *              .add_token("$pattern_set", token_set)
     *              .add_token("$pattern_setof", token_setof)
     *              .add_token("$pattern_taggedmode", token_taggedmode)
     *              .add_token("$pattern_assign", token_assign);
     *
     *          // set the input as follows ...
     *          const char* source = R"(
     *                ChildInformation ::= SET {name Name, dateOfBirth [0] Date}
     *                Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {givenName VisibleString, initial VisibleString, familyName VisibleString}
     *                EmployeeNumber ::= [APPLICATION 2] IMPLICIT  INTEGER
     *                Date ::= [APPLICATION 3] IMPLICIT  VisibleString
     *                PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
     *                     name Name,
     *                     title [0] VisibleString,
     *                     number EmployeeNumber,
     *                     dateOfHire [1] Date,
     *                     nameOfSpouse [2] Name,
     *                     children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}})"
     *
     *          p.get_config().set("handle_usertype", 1);
     *          p.parse(context, source);
     *          // after parsing, convert each word to a token object
     *          // array of parser::token*
     *          // [0] ChildInformation type token_usertype
     *          // [1] ::= type token_assign
     *          // [2] SET type set
     *          // ...
     *
     *          p.add_pattern("$pattern_builtintype")
     *              .add_pattern("$pattern_usertype")
     *              .add_pattern("$pattern_sequence")
     *              .add_pattern("$pattern_set")
     *              .add_pattern("$pattern_sequenceof $pattern_usertype")
     *              .add_pattern("$pattern_sequenceof $pattern_usertype DEFAULT")
     *              .add_pattern("$pattern_sequenceof $pattern_usertype DEFAULT {}")
     *              .add_pattern("{")
     *              .add_pattern(",")
     *              .add_pattern("}")
     *              .add_pattern("[$pattern_class 1] $pattern_builtintype")
     *              .add_pattern("[$pattern_class 1] $pattern_usertype")
     *              .add_pattern("[$pattern_class 1] $pattern_taggedmode $pattern_builtintype")
     *              .add_pattern("[$pattern_class 1] $pattern_taggedmode $pattern_usertype")
     *              .add_pattern("[$pattern_class 1] $pattern_taggedmode $pattern_sequence")
     *              .add_pattern("[$pattern_class 1] $pattern_taggedmode $pattern_set")
     *              .add_pattern("[1] $pattern_builtintype")
     *              .add_pattern("[1] $pattern_usertype")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_builtintype")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_usertype")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_sequence")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT {}")
     *              .add_pattern("[1] $pattern_taggedmode $pattern_set")
     *              .add_pattern("name $pattern_builtintype")
     *              .add_pattern("name $pattern_usertype")
     *              .add_pattern("name $pattern_sequence")
     *              .add_pattern("name $pattern_set")
     *              .add_pattern("name [$pattern_class 1] $pattern_builtintype")
     *              .add_pattern("name [$pattern_class 1] $pattern_usertype")
     *              .add_pattern("name [$pattern_class 1] $pattern_taggedmode $pattern_builtintype")
     *              .add_pattern("name [$pattern_class 1] $pattern_taggedmode $pattern_usertype")
     *              .add_pattern("name [$pattern_class 1] $pattern_taggedmode $pattern_sequence")
     *              .add_pattern("name [$pattern_class 1] $pattern_taggedmode $pattern_set")
     *              .add_pattern("name [1] $pattern_builtintype")
     *              .add_pattern("name [1] $pattern_usertype")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_builtintype")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_usertype")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_sequence")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT {}")
     *              .add_pattern("name [1] $pattern_taggedmode $pattern_set")
     *              .add_pattern("$pattern_assign");
     *
     *          // pattern search
     *          auto result = p.psearch(context);
     *          for (auto [range, pid] : result) {
     *              parser::search_result res;
     *              context.psearch_result(res, range, pid);
     *
     *              // all patterns matched
     *              _logger->writeln("pos [%i..%i] pattern[%i] %.*s", res.begin, res.end, pid, (unsigned)res.size, res.p);
     *          }
     *          auto resultex = p.psearch(context);
     *          for (auto [range, pid] : resultex) {
     *              parser::search_result res;
     *              context.psearch_result(res, range, pid);
     *
     *              // merge all overlapping intervals into one and output the result which should have only mutually exclusive intervals
     *              _logger->writeln("pos [%2i..%2i] pattern[%2i] %.*s", res.begin, res.end, pid, (unsigned)res.size, res.p);
     *          }
     *
     *          // source
     *          //  Date ::= [APPLICATION 3] IMPLICIT VisibleString
     *
     *          // result psearch
     *          //  pos [ 0] pattern[ 1] Date
     *          //  pos [ 1] pattern[44] ::=
     *          //  pos [ 2] pattern[12] [APPLICATION 3] IMPLICIT VisibleString
     *          //  pos [ 7] pattern[ 0] VisibleString
     *
     *          // result psearchex
     *          //  pos [ 0] pattern[ 1] Date
     *          //  pos [ 1] pattern[44] ::=
     *          //  pos [ 2] pattern[12] [APPLICATION 3] IMPLICIT VisibleString  // including pattern [0]
     *
     */
    std::multimap<range_t, unsigned> psearch(const parser::context& context);
    /**
     * @brief   pattern search
     * @remarks merge all overlapping patterns
     * @sa      t_merge_ovl_intervals
     */
    std::multimap<range_t, unsigned> psearchex(const parser::context& context);

    /**
     * @brief   add token
     * @param   const std::string& token [in]
     * @param   uint32 attr [inopt]
     * @param   uint32 tag [inopt]
     * @sample
     *          p.add_token("::=", token_assign).add_token("--", token_comments);
     */
    parser& add_token(const std::string& token, uint32 attr = 0, uint32 tag = 0);
    parser& add_tokenn(const char* token, size_t size, uint32 attr, uint32 tag);

    /*
     * @sample
     *          p.get_config().set("handle_token", 1);
     *          p.get_config().set("handle_quoted", 1);
     *          p.get_config().set("handle_comments", 1);
     *
     *          constexpr char input[] = R"a(product ::= SET "[" name cstring, price number "]" -- sample)a";
     *          p.add_token("::=", token_assign);
     *          p.parse(input); // ::= (token_assign), -- sample (token_comments)
     *          p.get_config().set("handle_quot_as_unquoted", 1);
     *          p.parse(input); // [ ]
     *          p.get_config().set("handle_quot_as_unquoted", 0);
     *          p.parse(input); // "[" "]"
     */
    t_key_value<std::string, uint16>& get_config();

    std::string typeof_token(uint32 type);
    std::string attrof_token(uint32 attr);

    /**
     * @brief   debug dump
     */
    void dump(const parser::context& context, basic_stream& bs);

   protected:
    /**
     * @brief   lookup
     * @param   const std::string& word [in]
     * @param   int& idx [out]
     * @param   uint32 flags [inopt]
     */
    bool lookup(const std::string& word, int& idx, uint32 flags = 0);
    /**
     * @brief   lookup
     * @param   int index [in]
     * @param   std::string& word [out]
     */
    bool rlookup(int index, std::string& word);
    /**
     * @brief   lookup
     * @param   const char* p [in]
     * @param   size_t size [in]
     * @param   std::string& token_name [out]
     * @param   uint32& token_type [out]
     * @param   uint32& token_tag [out]
     */
    bool lookup(const char* p, size_t size, std::string& token_name, uint32& token_type, uint32& token_tag);

    struct token_attr_tag {
        uint32 attr;
        uint32 tag;
        token_attr_tag(uint32 attr, uint32 tag) : attr(attr), tag(tag) {}
    };

    t_trie<char, char, token_attr_tag> _tokens;  // tokens
    t_trie<char> _dictionary;                    // lookup
    t_aho_corasick<int, token*>* _ac;            // multi-pattern search
    t_key_value<std::string, uint16> _keyvalue;  // get_config

    // debug
    typedef std::map<uint32, std::string> debug_info;
    debug_info _token_id;  // typeof_token
};

}  // namespace io
}  // namespace hotplace

#endif
