/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lexical_analyzer.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_LEXICALANALYZER__
#define __HOTPLACE_SDK_IO_PARSER_LEXICALANALYZER__

#include <hotplace/sdk/base/nostd/keyvalue.hpp>
#include <hotplace/sdk/base/pattern/trie.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/parser/types.hpp>
#include <hotplace/sdk/io/types.hpp>
#include <vector>

namespace hotplace {
namespace io {

enum parser_flag_t {
    flat_lookup_readonly = 1,  // see lexical_context::parse
    flag_repeat,
};

struct token_description {
    size_t idx;
    size_t index;
    uint32 type;
    // uint32 tag;
    size_t pos;
    size_t size;
    size_t line;
    const char* p;
};

struct search_result {
    bool match;
    const char* p;
    size_t size;
    size_t pos;
    size_t begidx;
    size_t endidx;

    search_result() : match(false), p(nullptr), size(0), pos(-1), begidx(-1), endidx(-1) {}
};

class lexical_token;
class lexical_context;
class lexical_analyzer;

/**
 * @brief   lexical token
 * @sa      lexical_analyzer::parse
 */
class lexical_token {
    friend class lexical_context;

   public:
    lexical_token();
    lexical_token(const lexical_token& other);

    lexical_token& init();
    lexical_token& increase();
    lexical_token& set_type(uint32 type);
    // lexical_token& set_tag(uint32 tag);
    lexical_token& update_pos(size_t pos);
    lexical_token& update_size(size_t size);
    lexical_token& newline();

    lexical_token& set_index(uint32 idx);
    uint32 get_index() const;
    uint32 get_tokenid() const;
    // uint32 get_tag() const;
    size_t get_pos() const;
    size_t get_size() const;
    size_t get_line() const;
    bool empty() const;
    size_t size() const;

    std::string as_string(const char* p) const;
    bool visit(const char* p, std::function<bool(const lexical_token* t)> f) const;

    lexical_token* clone() const;

   private:
    uint32 _tokenid;
    size_t _pos;
    size_t _size;
    size_t _line;
    uint32 _index;  // 0 reserved, start with 1
};

class lexical_context {
    friend class lexical_analyzer;

   public:
    lexical_context();
    ~lexical_context();

    void clear();

    void for_each(std::function<bool(const token_description* desc)> f) const;
    void for_each(const search_result& res, std::function<bool(const token_description* desc)> f) const;
    void walk(std::function<void(const char* p, const lexical_token*)> f);

    return_t get(size_t index, token_description* desc);

   protected:
    return_t init(const char* p, size_t size);

    return_t add_context_lextoken(const lexical_token& token, std::function<bool(int, lexical_token*)> hook = nullptr);
    lexical_token* last_lextoken();

   private:
    lexical_analyzer* _parser;
    const char* _p;
    size_t _size;
    std::vector<lexical_token*> _lextoken;  // lexical tokens
};

struct tokenptr_to_int_t {
    uint32 operator()(lexical_token* const* source, size_t index) const {
        const lexical_token* t = source[index];
        return t->get_tokenid();
    }
};

class lexical_analyzer {
    friend class lexical_context;

   public:
    lexical_analyzer();
    ~lexical_analyzer();

    lexical_analyzer(lexical_analyzer&& other) = delete;

    /**
     * @brief   add token
     * @param   const std::string& token [in]
     * @param   uint32 token [in]
     * @param   uint32 tag [inopt]
     * @sample
     *          p.add_token("::=", token_assign).add_token("--", token_comments);
     */
    lexical_analyzer& add_token(const std::string& token, uint32 tokenid);
    std::string nameof_token(uint32 token);

    /*
     * @brief   parse
     * @param   lexical_context& context [out]
     * @param   const char* p [in]
     * @param   size_t size [in]
     * @remarks
     */
    return_t parse(lexical_context& context, const char* p, size_t size, uint32 flags = 0);
    return_t parse(lexical_context& context, const char* p, uint32 flags = 0);
    return_t parse(lexical_context& context, const std::string& p, uint32 flags = 0);
    return_t parse(lexical_context& context, const basic_stream& p, uint32 flags = 0);

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

    /**
     * @brief   debug dump
     */
    void dump(const lexical_context& context, basic_stream& bs);

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
     // * @param   uint32& token_tag [out]
     */
    bool lookup(const char* p, size_t size, std::string& token_name, uint32& token_type /*, uint32& token_tag*/);

   private:
    mutable critical_section _lock;

    struct token_attr_tag {
        uint32 attr;
        // uint32 tag;
        token_attr_tag(uint32 attr) : attr(attr) {}
        // token_attr_tag(uint32 attr, uint32 tag) : attr(attr), tag(tag) {}
    };

    t_trie<char, char, token_attr_tag> _lextoken;  // add_token, lookup
    t_trie<char> _dictionary;                      // lookup, rlookup
    std::multimap<uint32, std::vector<uint32>> _patterns;

    t_key_value<std::string, uint16> _keyvalue;  // get_config

    // debug
    typedef std::map<uint32, std::string> debug_info;
    debug_info _token_dbg;  // nameof_token
};

}  // namespace io
}  // namespace hotplace

#endif
