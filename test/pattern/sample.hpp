/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_PATTERN__
#define __HOTPLACE_TEST_PATTERN__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

struct pattern_t {
    const char* pattern;
    unsigned len;
};

void test_kmp();
void test_aho_corasick_simple();
void test_aho_corasick();
void test_trie();
void test_trie_autocompletion();
void test_trie_lookup();
void test_trie_scan();
void test_suffixtree();
void test_suffixtree2();
void test_ukkonen();
void test_ukkonen2();
void test_lcp();
void test_wildcards();
void test_wildcards2();
void test_merge_ovl_intervals();
void test_aho_corasick_wildcard();
void test_aho_corasick_ignorecase();

#endif
