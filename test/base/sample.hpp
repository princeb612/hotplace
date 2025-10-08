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

void test_sharedinstance1();
void test_sharedinstance2();
void test_convert_endian();
void test_endian();
void test_byte_capacity_unsigned();
void test_byte_capacity_signed();
void test_maphint();
void test_mapinsert();
void test_binary();
void test_loglevel();
void test_nostd();
void test_range();
void test_merge();

#endif
