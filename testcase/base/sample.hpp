/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_BASE__
#define __HOTPLACE_TEST_BASE__

#include <stdio.h>

#include <hotplace/test.hpp>

enum option_flag_t : uint16 {
    option_attach = 1 << 0,
    option_thread = 1 << 1,
    option_notimecheck = 1 << 2,
};
struct OPTION : public CMDLINEOPTION {
    uint16 flags;

    OPTION() : CMDLINEOPTION(), flags(0) {}
};

struct pattern_t {
    const char* pattern;
    unsigned len;
};

extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void testcase_cmdline();
void testcase_testvector_cmdline();
void testcase_dumpmemory();
void testcase_narrowcast();
void testcase_pipeline();
void testcase_valist();
void testcase_testvector_valist();
void testcase_variant();

void testcase_graph();

void testcase_avltree();
void testcase_binary();
void testcase_btree();
void testcase_exception();
void testcase_findlte();
void testcase_int();
void testcase_list();
void testcase_map();
void testcase_pq();
void testcase_range();
void testcase_set();
void testcase_vector();

void testcase_aho_corasick();
void testcase_aho_corasick_wildcard();
void testcase_testvector_ahocorasick();
void testcase_kmp();
void testcase_testvector_kmp();
void testcase_suffixtree();
void testcase_testvector_regex();
void testcase_trie();
void testcase_ukkonen();
void testcase_wildcard();

void testcase_bufferio();
void testcase_stream();

void testcase_string();

void testcase_bignumber();
void testcase_testvector_bignumber();
void testcase_capacity();
void testcase_testvector_capacity();
void testcase_datetime();
void testcase_endian();
void testcase_floatingpoint();
void testcase_testvector_floatingpoint();
void testcase_ieee754();
void testcase_shared();
void testcase_signalwait_threads();

void testcase_consolecolor();
void testcase_loglevel();
void testcase_unittest();

#endif
