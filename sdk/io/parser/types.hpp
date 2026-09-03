/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_TYPES__
#define __HOTPLACE_SDK_IO_PARSER_TYPES__

#include <hotplace/sdk/io/types.hpp>

namespace hotplace {
namespace io {

enum token_t : uint32 {
    token_unknown = 0,
    token_alpha = 1,                // [a-zA-Z]
    token_number = 2,               // [0-9]
    token_floatingpoint = 3,        //
    token_space = 4,                // whitespace
    token_lparen = 5,               // (parentheses)
    token_rparen = 6,               // (parentheses)
    token_lbracket = 7,             // [brackets]
    token_rbracket = 8,             // [brackets]
    token_lbrace = 9,               // {braces}
    token_rbrace = 10,              // {braces}
    token_squote = 11,              // '
    token_dquote = 12,              // "
    token_greater = 13,             // >
    token_lesser = 14,              // <
    token_equal = 15,               // =
    token_plus = 16,                // +
    token_minus = 17,               // -
    token_multi = 18,               // *
    token_divide = 19,              // /
    token_colon = 20,               // :
    token_semicolon = 21,           // ;
    token_comma = 22,               // ,
    token_dot = 23,                 // .
    token_newline = 24,             // \n
    token_and = 25,                 // &&, |
    token_or = 26,                  // ||
    token_isequal = 27,             // ==
    token_notequal = 28,            // !=
    token_word = 29,                // [a-zA-Z0-9].*
    token_identifier = token_word,  //
    token_quot_string = 30,         // \"[a-zA-Z0-9].*\"
    token_comments = 31,            // lexical_token.comments .... until the newline
    token_assign = 32,              // =, ::=
    token_lvalue = 33,
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
    token_fromto,        // ..

    token_default,   // DEFAULT
    token_optional,  // OPTIONAL

    token_userdefine = 0x2000,

    token_eof = 0xffffffff,
};

token_t ascii2token(byte_t c);

class cfg_grammar;
class lalr_parser;
class lexical_analyzer;
class lexical_context;
class lexical_token;
class parse_tree;
class parse_resource;

}  // namespace io
}  // namespace hotplace

#endif
