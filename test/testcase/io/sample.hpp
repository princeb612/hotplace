/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TESTCASE_IO__
#define __HOTPLACE_TEST_TESTCASE_IO__

#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool flag_mlfq;
    bool flag_netlink;

    OPTION() : CMDLINEOPTION(), flag_mlfq(false), flag_netlink(false) {}
};

extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void testcase_payload();
void testcase_payload_quic();

void testcase_filestream();

void testcase_mlfq();
void testcase_netlink();

void testcase_parser();
void testcase_testvector_parser();

// parser

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
};

struct memberof_parser_token {
    uint32 operator()(const parser_token* source, size_t idx) const { return (nullptr != source) ? (uint32)source[idx].type : 0; }
};

typedef t_aho_corasick_reducer<uint32, parser_token, memberof_parser_token> asn1module_reducer_t;

void prepare_asn1module_reducer(asn1module_reducer_t& ac);

return_t prepare_lexer_asn1(lexical_analyzer& lexer);
return_t prepare_lexer_asn1_usertype(lexical_analyzer& lexer);
return_t ac_search(const asn1module_reducer_t& ac, const char* input, std::vector<parser_token>& tokens, std::multimap<range_t, size_t>& results);
return_t ac_printall(const asn1module_reducer_t& ac, const std::vector<parser_token>& tokens, const std::multimap<range_t, size_t>& results);
return_t ac_search_and_printall(const asn1module_reducer_t& ac, const char* input);

#endif
