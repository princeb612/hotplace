/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_TYPES__
#define __HOTPLACE_SDK_IO_PARSER_TYPES__

#include <hotplace/sdk/io/types.hpp>

namespace hotplace {
namespace io {

/**
 * runtime
 *   auto symid = token_resource::get_instance()->nameof(token_identifier);
 *
 * compile-time
 *   SYMBOL_FP       | token_floatingpoint | "fp"
 *   SYMBOL_ID       | token_identifier    | "id"
 *   SYMBOL_NUM      | token_number        | "num"
 *   SYMBOL_QSTR     | token_quot_string   | "quot_string"
 *   SYMBOL_USERTYPE | token_usertype      | "usertype"
 */
#define SYMBOL_FP "fp"
#define SYMBOL_ID "id"
#define SYMBOL_NUM "num"
#define SYMBOL_QSTR "quot_string"
#define SYMBOL_USERTYPE "usertype"

enum token_t : uint32 {
    token_unknown = 0,
    token_alpha = 1,                // [a-zA-Z]
    token_number = 2,               // [0-9]
    token_word = 3,                 // [a-zA-Z0-9].*
    token_identifier = token_word,  //
    token_floatingpoint = 4,        //
    token_space = 5,                // whitespace
    token_lparen = 6,               // (parentheses)
    token_rparen = 7,               // (parentheses)
    token_lbracket = 8,             // [brackets]
    token_rbracket = 9,             // [brackets]
    token_lbrace = 10,              // {braces}
    token_rbrace = 11,              // {braces}
    token_comments = 12,            // lexical_token.comments .... until the newline
    token_assign = 13,              // =, ::=
    token_lvalue = 14,              //
    token_squote = 15,              // '
    token_dquote = 16,              // "
    token_greater = 17,             // >
    token_lesser = 18,              // <, less-than indicator, exclusive boundary indicator
    token_equal = 19,               // =
    token_plus = 20,                // +
    token_minus = 21,               // -
    token_dash = token_minus,       //
    token_multi = 22,               // *
    token_divide = 23,              // /
    token_colon = 24,               // :
    token_semicolon = 25,           // ;
    token_comma = 26,               // ,
    token_dot = 27,                 // .
    token_newline = 28,             // \n
    token_and = 29,                 // &&, |
    token_or = 30,                  // ||
    token_isequal = 31,             // ==
    token_notequal = 32,            // !=
    token_quot_string = 33,         // \"[a-zA-Z0-9].*\"
    token_emphasis = 34,
    token_type = 35,
    token_usertype = 36,
    token_element = 37,
    token_phrase = 38,
    token_sentence = 39,

    // ASN.1
    token_asn1 = 0x1000,

    token_builtintype,
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
    token_of,
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
    token_cstring,
    token_bmpstring,
    token_date,
    token_timeofday,
    token_datetime,
    token_duration,
    token_any,
    token_choice,

    token_boolvalue,
    token_true,   // TRUE
    token_false,  // FALSE

    token_class,
    token_universal,    // UNIVERSAL
    token_application,  // APPLICATION
    token_private,      // PRIVATE

    token_taggedmode,
    token_implicit,
    token_explicit,

    token_namedtype,
    token_tag,
    token_taggedtype,
    token_referencedtype,

    token_union,         // |
    token_intersection,  // INTERSECTION
    token_except,        // EXCEPT
    token_allexcept,     // ALL EXCEPT
    token_size,          // SIZE
    token_from,          // FROM
    token_pattern,       // PATTERN
    token_min,           // MIN
    token_max,           // MAX
    token_fromto,        // .. range separator, range operator
    token_range = token_fromto,

    token_default,   // DEFAULT
    token_optional,  // OPTIONAL

    token_definitions,
    token_automatic,
    token_begin,
    token_end,
    token_tags,
    token_exports,
    token_imports,
    token_all,
    token_extensibility,
    token_implied,

    token_userdefine = 0x2000,

    token_eof = 0xffffffff,
};

token_t ascii2token(byte_t c);

using native_token_t = std::underlying_type<token_t>::type;

enum class parser_action_t {
    shift,
    reduce,
    accept,
    error,  // conflict
};

struct parser_action {
    parser_action_t type;
    uint32 target;  // next state on shift, rule id on reduce

    parser_action(parser_action_t a = parser_action_t::error, uint32 t = -1) : type(a), target(t) {}
};

struct parser_production {
    uint32 id;
    std::string lhs;
    std::vector<std::string> rhs;
};

struct parser_token {
    uint32 type;        // symbol, see token_t
    std::string value;  // lexeme

    parser_token() : type(0), value() {}
    parser_token(uint32 t) : type(t), value() {}
    parser_token(uint32 t, const std::string& v) : type(t), value(v) {}

    bool operator<(const parser_token& other) const {
        if (type != other.type) return type < other.type;
        return value < other.value;
    }
    bool operator==(const parser_token& other) const { return (type == other.type) && (value == other.value); }
    bool operator!=(const parser_token& other) const { return !(*this == other); }
    bool operator!=(int null_val) const { return static_cast<int>(type) != null_val; }
};

struct parse_treenode;

class cfg_grammar;
class lalr_parser;
class lexical_analyzer;
class lexical_context;
class lexical_token;
class parse_tree;
class parse_tree_visitor;
class parse_resource;

}  // namespace io
}  // namespace hotplace

#endif
