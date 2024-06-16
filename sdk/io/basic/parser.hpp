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
};

struct token_description {
    uint32 attr;
    uint32 index;
    uint32 type;
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
        token& update_pos(size_t pos);
        token& update_size(size_t size);
        token& newline();

        token& set_index(uint32 idx);
        uint32 get_index() const;
        uint32 get_type() const;
        size_t get_pos() const;
        size_t get_size() const;
        size_t get_line() const;
        bool empty();
        size_t size();

        std::string as_string(const char* p);
        void visit(const char* p, std::function<void(const token* t)> f);

        parser::token* clone();

       private:
        uint32 _type;
        size_t _pos;
        size_t _size;
        size_t _line;
        uint32 _index;
    };

    class context {
       public:
        context();
        ~context();

        return_t parse(parser* obj, const char* p, size_t size);
        search_result csearch(parser* obj, const char* pattern, size_t size_pattern, unsigned int pos = 0) const;
        search_result csearch(parser* obj, const std::string& pattern, unsigned int pos = 0) const;
        search_result wsearch(parser* obj, const context& pattern, unsigned int pos = 0) const;
        bool compare(parser* obj, const parser::context& rhs) const;

        return_t add_token_if(std::function<void(int, parser::token*)> hook = nullptr);
        void clear();

        void for_each(std::function<void(const token_description* desc)> f) const;
        void walk(std::function<void(const char* p, const parser::token*)> f);

       protected:
        return_t init(parser* obj, const char* p, size_t size);
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

    /*
     * @brief   parse
     * @param   parser::context& context [out]
     * @param   const char* p [in]
     * @param   size_t size [in]
     * @remarks
     */
    return_t parse(parser::context& context, const char* p, size_t size);
    /**
     * @brief   pattern search (character search)
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
    /**
     * @brief   pattern search (word search)
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

    /**
     * @brief   compare (ignore white spaces)
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
     * @brief   add token
     * @param   const std::string token [in]
     * @param   int attr [inopt]
     * @sample
     *          p.add_token("::=", token_assign).add_token("--", token_comments);
     */
    parser& add_token(const std::string token, int attr = 0);

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

    void dump(const parser::context& context, basic_stream& bs);

   protected:
    bool lookup(const std::string& word, int& idx);
    bool lookup(int index, std::string& word);
    bool token_match(const char* p, std::string& token_name, int& token_type);

    // lookup by word or index
    struct dictionary_t {
        std::map<std::string, int> index;   // map<word, index>
        std::map<int, std::string> rindex;  // map<index, word>
    };
    typedef std::multimap<char, std::pair<std::string, int>> tokens_t;

    dictionary_t _dictionary;                    // lookup
    tokens_t _tokens;                            // token_match
    t_key_value<std::string, uint16> _keyvalue;  // get_config

    // debug
    typedef std::map<uint32, std::string> debug_info;
    debug_info _token_id;  // typeof_token
};

}  // namespace io
}  // namespace hotplace

#endif
