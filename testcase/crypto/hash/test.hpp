/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_CRYPTO_HASH__
#define __HOTPLACE_TEST_CRYPTO_HASH__

#include <hotplace/sdk/sdk.hpp>

void test_hash_routine(hash_algorithm_t algorithm, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size);
return_t test_hash_routine(hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text);

#endif
