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
#include <hotplace/test/test.hpp>

extern test_case _test_case;
extern t_shared_instance<logger> _logger;

void test_bignumber();
void test_binary();
void test_bufferio();
void test_capacity();
void test_cmdline();
void test_consolecolor();
void test_datetime();
void test_dumpmemory();
void test_endian();
void test_ieee754();
void test_loglevel();
void test_shared();
void test_stream();
void test_string();
void test_valist();
void test_variant();

#endif
