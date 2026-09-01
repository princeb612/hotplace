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

const parser_token_resource parser_basic_tokens[] = {
    {token_alpha, "alpha"},
    {token_number, "num"},        // number
    {token_floatingpoint, "fp"},  // floatingpoint
    {token_space, "space"},
    {token_lparen, "lparen"},
    {token_rparen, "rparen"},
    {token_lbracket, "lbracket"},
    {token_rbracket, "rbracket"},
    {token_lbrace, "lbrace"},
    {token_rbrace, "rbrace"},
    {token_squote, "squote"},
    {token_dquote, "dquote"},
    {token_greater, "greater"},
    {token_lesser, "lesser"},
    {token_equal, "equal"},
    {token_plus, "plus"},
    {token_minus, "minus"},
    {token_multi, "multi"},
    {token_divide, "divide"},
    {token_colon, "colon"},
    {token_semicolon, "semicolon"},
    {token_comma, "comma"},
    {token_dot, "dot"},
    {token_newline, "newline"},
    {token_and, "and"},
    {token_or, "or"},
    {token_isequal, "=="},
    {token_notequal, "!="},
    {token_identifier, "id"},  // identifier
    {token_quot_string, "quot_string"},
    {token_comments, "comments"},
    {token_assign, "assign"},
    {token_lvalue, "lvalue"},
    {token_emphasis, "emphasis"},
    {token_type, "type"},
    {token_usertype, "usertype"},
    {token_element, "element"},
    {token_phrase, "phrase"},
    {token_sentence, "sentence"},
};
const size_t sizeof_parser_basic_tokens = RTL_NUMBER_OF(parser_basic_tokens);

const parser_token_resource parser_asn1_tokens[] = {
    {token_assign, "::="},
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
    {token_of, "OF"},
    {token_sequence, "SEQUENCE"},
    {token_set, "SET"},
    {token_numstring, "NumericString"},
    {token_printstring, "PrintableString"},
    {token_t61string, "TeletexString"},
    {token_videotexstring, "VideotexString"},
    {token_ia5string, "IA5String"},
    {token_utctime, "UTCTime"},
    {token_generalizedtime, "GeneralizedTime"},
    {token_graphicstring, "GraphicString"},
    {token_visiblestring, "VisibleString"},
    {token_genaralstring, "GeneralString"},
    {token_universalstring, "UniversalString"},
    {token_cstring, "CHARACTER STRING"},
    {token_bmpstring, "BMPString"},
    {token_date, "DATE"},
    {token_timeofday, "TIME-OF-DAY"},
    {token_datetime, "DATE-TIME"},
    {token_duration, "DURATION"},
    {token_any, "ANY"},
    {token_choice, "CHOICE"},
    {token_comments, "--"},
    {token_true, "TRUE"},
    {token_false, "FALSE"},
    {token_taggedmode, "tagged mode"},
    {token_class, "class"},
    {token_universal, "UNIVERSAL"},
    {token_application, "APPLICATION"},
    {token_private, "PRIVATE"},
    {token_implicit, "IMPLICIT"},
    {token_explicit, "EXPLICIT"},
    {token_union, "|"},
    {token_intersection, "INTERSECTION"},
    {token_except, "EXCEPT"},
    {token_allexcept, "ALL EXCEPT"},
    {token_size, "SIZE"},
    {token_from, "FROM"},
    {token_pattern, "PATTERN"},
    {token_default, "DEFAULT"},
    {token_optional, "OPTIONAL"},
    {token_min, "MIN"},
    {token_max, "MAX"},
    {token_fromto, ".."},
};
const size_t sizeof_parser_asn1_tokens = RTL_NUMBER_OF(parser_asn1_tokens);

}  // namespace io
}  // namespace hotplace
