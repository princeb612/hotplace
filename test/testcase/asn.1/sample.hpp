/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TESTCASE_ASN1__
#define __HOTPLACE_TEST_TESTCASE_ASN1__

#include <stdio.h>

#include <hotplace/test/test.hpp>

#define FLAG_DUMMY_POC_TOKEN 1

void dump_parse_tree(asn1_runtime* runtime, const parse_tree* pt);
void parse_notation(asn1_runtime* runtime, const char* notation);
void parse_reconst_notation(asn1_runtime* runtime, const char* notation, const char* expect = nullptr);
void test_asn1parser(parser_t& parser, const char* text, const char* input, uint16 flags);
void test_asn1parser(lexical_analyzer& lexer, parser_t& parser, const char* text, const char* input, uint16 flags);

void testcase_basic1();
void testcase_basic2();
void testcase_constraints();
void testcase_testvector_der();
void testcase_parser();
void testcase_testvector_parser();
void testcase_basic3();
void testcase_publish();
void testcase_loader();

#endif
