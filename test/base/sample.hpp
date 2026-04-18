/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_BASE__
#define __HOTPLACE_TEST_BASE__

#include <stdio.h>

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/base/pattern/test.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int attach;

    OPTION() : CMDLINEOPTION(), attach(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void testcase_binary();
void testcase_cmdline();
void testcase_dumpmemory();
void testcase_valist();
void testcase_variant();

void testcase_graph();

void testcase_avltree();
void testcase_btree();
void testcase_exception();
void testcase_findlte();
void testcase_list();
void testcase_map();
void testcase_ovl();
void testcase_pq();
void testcase_range();
void testcase_vector();

void testcase_aho_corasick();
void testcase_aho_corasick_wildcard();
void testcase_kmp();
void testcase_suffixtree();
void testcase_trie();
void testcase_ukkonen();
void testcase_wildcard();

void testcase_bufferio();
void testcase_stream();

void testcase_string();

void testcase_bignumber();
void testcase_capacity();
void testcase_datetime();
void testcase_endian();
void testcase_ieee754();
void testcase_shared();
void testcase_signalwait_threads();

void testcase_consolecolor();
void testcase_loglevel();
void testcase_unittest();

#endif
