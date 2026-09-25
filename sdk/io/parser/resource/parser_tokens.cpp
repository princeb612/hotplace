/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_tokens.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

const parser_token_resource parser_symbol_tokens[] = {
    {token_alpha, "alpha"},
    {token_amp, "amp"},
    {token_assign, "assign"},
    {token_asterisk, "*"},
    {token_at, "at"},
    {token_backtick, "`"},
    {token_bslash, "\\"},
    {token_caret, "^"},
    {token_colon, "colon"},
    {token_comma, "comma"},
    {token_comments, "comments"},
    {token_dash, "dash"},
    {token_dot, "dot"},
    {token_dquote, "dquote"},
    {token_element, "element"},
    {token_emphasis, "emphasis"},
    {token_equal, "equal"},
    {token_exclamation, "!"},
    {token_floatingpoint, SYMBOL_FP},  // floatingpoint
    {token_greater, "greater"},
    {token_identifier, SYMBOL_ID},  // identifier
    {token_isequal, "=="},
    {token_lbrace, "lbrace"},
    {token_lbracket, "lbracket"},
    {token_lesser, "lesser"},
    {token_lparen, "lparen"},
    {token_lvalue, "lvalue"},
    {token_newline, "newline"},
    {token_notequal, "!="},
    {token_number, SYMBOL_NUM},  // number
    {token_paramtype, SYMBOL_PARAMTYPE},
    {token_paramvalue, SYMBOL_PARAMVALUE},
    {token_percent, "%"},
    {token_phrase, "phrase"},
    {token_pipe, "|"},
    {token_plus, "+"},
    {token_question, "?"},
    {token_quot_string, SYMBOL_QSTR},
    {token_rbrace, "rbrace"},
    {token_rbracket, "rbracket"},
    {token_rparen, "rparen"},
    {token_semicolon, "semicolon"},
    {token_sentence, "sentence"},
    {token_sharp, "#"},
    {token_slash, "/"},
    {token_space, "space"},
    {token_squote, "squote"},
    {token_tilde, "~"},
    {token_type, "type"},
    {token_underline, "_"},
    {token_userparamtype, SYMBOL_USERPARAMTYPE},
    {token_usertype, SYMBOL_USERTYPE},
    {token_eof, "$"},
    {token_ellipsis, "ellipsis"},
    {token_range, "range"},
};
const size_t sizeof_parser_symbol_tokens = RTL_NUMBER_OF(parser_symbol_tokens);

const parser_token_resource parser_basic_tokens[] = {
    // clang-format off
    {token_colon, ":"},
    {token_lbrace, "{"},
    {token_lbracket, "["},
    {token_lparen, "("},
    {token_rbrace, "}"},
    {token_rbracket, "]"},
    {token_rparen, ")"},
    {token_semicolon, ";"},
    // clang-format on
};
const size_t sizeof_parser_basic_tokens = RTL_NUMBER_OF(parser_basic_tokens);

const struct parser_token_resource parser_asn1_tokens[] = {
    {token_assign, "::="},
    {token_comments, "--"},
    {token_ellipsis, "..."},

    // BitStringType ~ RelativeOIDType
    {token_bool, "BOOLEAN"},
    {token_int, "INTEGER"},
    {token_bitstring, "BIT STRING"},
    {token_octstring, "OCTET STRING"},
    {token_null, "NULL"},
    {token_oid, "OBJECT IDENTIFIER"},
    {token_objdesc, "ObjectDescriptor"},
    {token_extern, "EXTERNAL"},
    {token_real, "REAL"},
    {token_enum, "ENUMERATED"},
    {token_embedpdv, "EMBEDDED PDV"},
    {token_utf8string, "UTF8String"},
    {token_reloid, "RELATIVE-OID"},
    {token_numstring, "NumericString"},
    {token_printstring, "PrintableString"},
    {token_t61string, "TeletexString"},
    {token_t61string, "T61String"},
    {token_videotexstring, "VideotexString"},
    {token_ia5string, "IA5String"},
    {token_utctime, "UTCTime"},
    {token_generalizedtime, "GeneralizedTime"},
    {token_graphicstring, "GraphicString"},
    {token_visiblestring, "VisibleString"},
    {token_visiblestring, "ISO646String"},
    {token_genaralstring, "GeneralString"},
    {token_universalstring, "UniversalString"},
    {token_cstring, "CHARACTER STRING"},
    {token_bmpstring, "BMPString"},
    {token_date, "DATE"},
    {token_timeofday, "TIME-OF-DAY"},
    {token_datetime, "DATE-TIME"},
    {token_duration, "DURATION"},
    {token_any, "ANY"},
    // SequenceType ~ SetOfType
    {token_sequence, "SEQUENCE"},
    {token_set, "SET"},
    {token_choice, "CHOICE"},
    {token_of, "OF"},

    // BooleanValue
    {token_true, "TRUE"},
    {token_false, "FALSE"},
    // Class
    {token_universal, "UNIVERSAL"},
    {token_application, "APPLICATION"},
    {token_private, "PRIVATE"},
    // cf. Tag
    {token_implicit, "IMPLICIT"},
    {token_explicit, "EXPLICIT"},
    // cf. NamedType
    {token_default, "DEFAULT"},
    {token_optional, "OPTIONAL"},

    // constraints
    {token_union, "|"},
    {token_intersection, "INTERSECTION"},
    {token_intersection, "INTERSECT"},
    {token_except, "EXCEPT"},
    {token_allexcept, "ALL EXCEPT"},
    {token_size, "SIZE"},
    {token_from, "FROM"},
    {token_pattern, "PATTERN"},
    {token_max, "MAX"},
    {token_min, "MIN"},
    {token_range, ".."},
    // module
    {token_definitions, "DEFINITIONS"},
    {token_automatic, "AUTOMATIC"},
    {token_tags, "TAGS"},
    {token_begin, "BEGIN"},
    {token_end, "END"},
    // exports/imports
    {token_exports, "EXPORTS"},
    {token_imports, "IMPORTS"},
    {token_all, "ALL"},
    {token_extensibility, "EXTENSIBILITY"},
    {token_implied, "IMPLIED"},
    // information object class
    {token_class, "CLASS"},
    {token_with, "WITH"},
    {token_syntax, "SYNTAX"},
    {token_unique, "UNIQUE"},
};
const size_t sizeof_parser_asn1_tokens = RTL_NUMBER_OF(parser_asn1_tokens);

}  // namespace io
}  // namespace hotplace
