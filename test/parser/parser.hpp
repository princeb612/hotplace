/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_PARSER__
#define __HOTPLACE_SDK_IO_BASIC_PARSER__

#include <sdk/base.hpp>

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

    token_identifier = 32,   // [a-zA-Z0-9].*
    token_quot_string = 33,  // \"[a-zA-Z0-9].*\"
    token_comments = 34,     // token.comments .... until the newline
};

enum parser_attribute {
    parser_attr_assign,
    parser_attr_quot,
    parser_attr_comments,
};

struct token_description {
    uint32 type;
    size_t pos;
    size_t size;
    size_t line;
    int index;
    const char* p;
};

class parser_context {
   public:
    /**
     * @brief   token
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

        token& set_index(uint32 id);
        uint32 get_index() const;
        uint32 get_type() const;
        size_t get_pos() const;
        size_t get_size() const;
        size_t get_line() const;
        bool empty();
        size_t size();

        std::string as_string(const char* p);
        void visit(const char* p, std::function<void(const token* t)> f);

        token* clone();

       private:
        uint32 _type;
        size_t _pos;
        size_t _size;
        size_t _line;
        uint32 _id;
    };

   public:
    parser_context();
    ~parser_context();

    return_t init(const char* p, size_t size);
    return_t add_token_if(std::function<void(token*)> hook = nullptr);
    void clear();

    token& get_token();

    void learn();

    void for_each(std::function<void(const token_description* desc)> f);

   private:
    const char* _p;
    size_t _size;
    std::list<token*> _tokens;
    token _token;
};

/**
 * @brief   parse
 * @sample
 */
class parser {
   public:
    parser();

    /*
     * @brief   parse
     * @remarks
     *          tokenize
     *          handle quoted string
     *          handle token
     */
    return_t parse(parser_context& context, const char* p, size_t size);
    // parser& apply(parser_context& context);

    parser& add_token(const std::string token, int attr = 0);
    parser& add_rule(const std::string rule);
    // parser& learn();

    /*
     * @sample
     *          p.get_config().set("handle_token", 1);
     *          p.get_config().set("handle_quoted", 1);
     *          p.get_config().set("handle_comments", 1);
     */
    t_key_value<std::string, uint16>& get_config();

   protected:
    void lookup(const std::string& word, int& idx);
    // void lookup_token(const std::string& word, int& attr);

    typedef std::map<std::string, int> dictionary_t;  // map<word, index>
    typedef std::multimap<char, std::pair<std::string, int>> tokens_t;

    dictionary_t _dictionary;
    tokens_t _tokens;
    t_key_value<std::string, uint16> _keyvalue;
};

}  // namespace io
}  // namespace hotplace

#endif
