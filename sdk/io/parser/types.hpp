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
#include <map>
#include <set>
#include <stack>
#include <vector>

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
#define SYMBOL_USERPARAMTYPE "userparamtype"
#define SYMBOL_PARAMTYPE "paramtype"
#define SYMBOL_PARAMVALUE "paramvalue"

enum token_t : uint32 {
    token_unknown = 0,
    token_newline = 0x0a,             // \n
    token_space = 0x20,               // whitespace
    token_exclamation = 0x21,         //
    token_dquote = 0x22,              // "
    token_sharp = 0x23,               // #
    token_dollar = 0x24,              // $
    token_percent = 0x25,             // %
    token_amp = 0x26,                 // &, |
    token_and = token_amp,            //
    token_squote = 0x27,              // '
    token_apostrophe = token_squote,  //
    token_lparen = 0x28,              // (parentheses
    token_rparen = 0x29,              // parentheses)
    token_asterisk = 0x2a,            // *
    token_multi = token_asterisk,     //
    token_plus = 0x2b,                // +
    token_comma = 0x2c,               // ,
    token_dash = 0x2d,                // -
    token_minus = token_dash,         //
    token_dot = 0x2e,                 // .
    token_slash = 0x2f,               // /
    token_divide = token_slash,       //
    token_number = 0x30,              // [0-9]
    token_colon = 0x3a,               // :
    token_semicolon = 0x3b,           // ;
    token_lesser = 0x3c,              // <, less-than indicator, exclusive boundary indicator
    token_equal = 0x3d,               // =
    token_greater = 0x3e,             // >
    token_question = 0x3f,            // >
    token_at = 0x40,                  // @
    token_alpha = 0x41,               // [a-zA-Z]
    token_lbracket = 0x5b,            // [
    token_bslash = 0x5c,              // '\\'
    token_rbracket = 0x5d,            // ]
    token_caret = 0x5e,               // ^
    token_underline = 0x5f,           // _
    token_backtick = 0x60,            // `
    token_grave = token_backtick,     //
    token_lbrace = 0x7b,              // {
    token_pipe = 0x7c,                // |
    token_or = token_pipe,            //
    token_rbrace = 0x7d,              // }
    token_tilde = 0x7e,               // ~

    token_symbol = 0x100,
    token_word,                     // [a-zA-Z0-9].*
    token_id = token_word,          //
    token_identifier = token_word,  //
    token_floatingpoint,            //
    token_comments,                 // lexical_token.comments .... until the newline
    token_assign,                   // =, ::=
    token_lvalue,                   //
    token_isequal,                  // ==
    token_notequal,                 // !=
    token_quot_string,              // \"[a-zA-Z0-9].*\"
    token_emphasis,
    token_type,
    token_usertype,
    token_element,
    token_phrase,
    token_sentence,
    token_ellipsis,
    token_extension_marker = token_ellipsis,  // ...

    // ASN.1
    token_asn1 = 0x1000,

    // token_builtintype,
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
    token_numstring,
    token_printstring,
    token_t61string,  // teletexstring
    token_videotexstring,
    token_ia5string,
    token_utctime,
    token_generalizedtime,
    token_graphicstring,
    token_visiblestring,  // iso646string
    token_genaralstring,
    token_universalstring,
    token_cstring,
    token_bmpstring,
    token_date,
    token_timeofday,
    token_datetime,
    token_duration,
    token_any,

    token_sequence,
    token_set,
    token_choice,
    token_of,

    token_true,         // TRUE
    token_false,        // FALSE
    token_universal,    // UNIVERSAL
    token_application,  // APPLICATION
    token_private,      // PRIVATE

    token_implicit,
    token_explicit,

    token_default,   // DEFAULT
    token_optional,  // OPTIONAL

    token_union,         // |
    token_intersection,  // INTERSECTION, INTERSECT
    token_except,        // EXCEPT
    token_allexcept,     // ALL EXCEPT
    token_size,          // SIZE
    token_from,          // FROM
    token_pattern,       // PATTERN
    token_min,           // MIN
    token_max,           // MAX
    token_range,         // .. range separator, range operator
    token_fromto = token_range,

    // module
    token_definitions,
    token_automatic,
    token_tags,
    token_begin,
    token_end,
    // exports/imports
    token_exports,
    token_imports,
    token_all,
    token_extensibility,
    token_implied,
    // parameterized
    token_userparamtype,
    token_paramtype,
    token_paramvalue,
    // information object class
    token_class,
    token_with,
    token_syntax,
    token_unique,

    token_userdefine = 0x2000,  // 0~0x1fff reserved

    token_eof = 0xffffffff,
};

token_t ascii2token(byte_t c);

using native_token_t = std::underlying_type<token_t>::type;

enum class parser_type_t {
    unknown,
    lalr1,
    glr,
};

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

struct LR0_item {
    uint32 production_id;
    size_t dot_pos;

    bool operator<(const LR0_item& other) const {
        if (production_id != other.production_id) return production_id < other.production_id;
        return dot_pos < other.dot_pos;
    }
    bool operator==(const LR0_item& other) const { return production_id == other.production_id && dot_pos == other.dot_pos; }
};

struct LR1_item {
    uint32 production_id;
    size_t dot_pos;
    std::string lookahead;

    bool operator<(const LR1_item& other) const {
        if (production_id != other.production_id) return production_id < other.production_id;
        if (dot_pos != other.dot_pos) return dot_pos < other.dot_pos;
        return lookahead < other.lookahead;
    }
};

typedef std::vector<parser_production> parser_production_t;
typedef std::set<std::string> parser_terminals_t;
typedef std::map<std::string, std::set<std::string>> parser_first_sets_t;
typedef std::map<std::string, std::set<std::string>> parser_follow_sets_t;
typedef std::vector<std::set<LR0_item>> parser_lr0_states_t;
typedef std::map<std::pair<uint32, std::string>, uint32> parser_lr0_goto_t;
typedef std::map<std::pair<uint32, std::string>, uint32> parser_goto_table_t;
typedef std::map<std::pair<uint32, std::string>, parser_action> parser_lalr1_action_table_t;
typedef std::multimap<std::pair<uint32, std::string>, parser_action> parser_glr_action_table_t;

struct parser_temporary_context_t {
    std::map<std::string, std::set<std::string>> first_sets;
    std::map<std::string, std::set<std::string>> follow_sets;
    std::vector<std::set<LR0_item>> lr0_states;
    std::map<std::pair<uint32, std::string>, uint32> lr0_goto;
    void clear() {
        first_sets.clear();
        follow_sets.clear();
        lr0_states.clear();
        lr0_goto.clear();
    }
};

class cfg_grammar;
class lalr1_parser;
class lexical_analyzer;
class lexical_context;
class lexical_token;
class parse_tree;
class parse_tree_visitor;
class parse_resource;

class parser_t {
   public:
    virtual ~parser_t() = default;

    virtual void set_grammar(const cfg_grammar& g) = 0;
    virtual void set_grammar(cfg_grammar&& grammar) = 0;
    virtual return_t learn() = 0;
    virtual bool ready() const = 0;
    virtual return_t parse(const std::vector<parser_token>& tokens, parse_tree* pt = nullptr) = 0;
    virtual parser_type_t get_type() const = 0;
};

static inline bool is_asn1type(native_token_t id) { return (token_bool <= id) && (token_of >= id); }

}  // namespace io
}  // namespace hotplace

#endif
