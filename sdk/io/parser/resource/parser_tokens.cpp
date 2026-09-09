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
const size_t sizeof_parser_symbol_tokens = RTL_NUMBER_OF(parser_symbol_tokens);

const parser_token_resource parser_basic_tokens[] = {
    // clang-format off
    {token_lparen, "("},
    {token_rparen, ")"},
    {token_lbracket, "["},
    {token_rbracket, "]"},
    {token_lbrace, "{"},
    {token_rbrace, "}"},
    {token_colon, ";"},
    // clang-format on
};
const size_t sizeof_parser_basic_tokens = RTL_NUMBER_OF(parser_basic_tokens);

}  // namespace io
}  // namespace hotplace
