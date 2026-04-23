/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_CRYPTO_KEY_TESTVECTOR__
#define __HOTPLACE_TEST_CRYPTO_KEY_TESTVECTOR__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/testcase/test.hpp>

struct test_vector_rfc7919_t {
    const char* desc;
    uint32 nid;
    const char* p;
    const char* q;
    const char* g;
};
extern const test_vector_rfc7919_t test_vector_rfc7919[];
extern const size_t sizeof_test_vector_rfc7919;

#endif
