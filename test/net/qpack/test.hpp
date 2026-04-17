/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_NET_QPACK__
#define __HOTPLACE_TEST_NET_QPACK__

#include <hotplace/test/test.hpp>

void dump_qpack_session_routine(const char* stream, size_t size);

void test_expect(binary_t& bin, const char* expect, const char* func, const char* text, ...);
void test_dump(binary_t& bin, const char* text, ...);

#endif
