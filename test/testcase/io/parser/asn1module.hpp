/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1module.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TESTCASE_IO_PARSER_ASN1MODULE__
#define __HOTPLACE_TEST_TESTCASE_IO_PARSER_ASN1MODULE__

#include <hotplace/test/test.hpp>

// test/testcase/io/parser/
// test/testcase/asn.1/

enum vtoken_t : native_token_t {
    vtoken_symbol = token_userdefine + 1,
    vtoken_header_clause,
    vtoken_exports_clause,
    vtoken_imports_clause,
    vtoken_header_block_start,
    vtoken_header_block_end,
    vtoken_exports_clause_start,
    vtoken_exports_clause_end,
    vtoken_imports_clause_start,
    vtoken_imports_clause_end,
    vtoken_endof_module,
};

struct memberof_parser_token {
    uint32 operator()(const parser_token* source, size_t idx) const { return (nullptr != source) ? (uint32)source[idx].type : 0; }
};

typedef t_aho_corasick_reducer<uint32, parser_token, memberof_parser_token> asn1module_reducer_t;

return_t prepare_lexer_asn1(lexical_analyzer& lexer);
return_t prepare_lexer_asn1_usertype(lexical_analyzer& lexer);

return_t prepare_asn1module_reducer(asn1module_reducer_t& ac);
return_t ac_search(const asn1module_reducer_t& ac, const char* input, size_t size, std::vector<parser_token>& tokens, std::multimap<range_t, size_t>& results);
return_t ac_printall(const asn1module_reducer_t& ac, const std::vector<parser_token>& tokens, const std::multimap<range_t, size_t>& results);
return_t ac_search_and_printall(const asn1module_reducer_t& ac, const char* input, size_t size);

// LALR(1)
return_t prepare_asn1notation_grammar(parser_t& parser);
return_t prepare_asn1module_grammar(parser_t& parser);
// GLR
return_t prepare_asn1parameterized_grammar(parser_t& parser);
return_t prepare_asn1_grammar(parser_t& parser);

void test_asn1parser(parser_t& parser, const char* text, const char* input);
void test_asn1parser(lexical_analyzer& lexer, parser_t& parser, const char* text, const char* input);
void dump_parse_tree(parse_tree& pt);

parser_t& get_lalr_parser_asn1notation();
parser_t& get_glr_parser_asn1parameterized();
parser_t& get_glr_parser_asn1();

#endif
