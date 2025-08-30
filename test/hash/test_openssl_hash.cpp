/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// no plan
// class wincrypt_hash : public hash_t

void test_hash_routine(hash_algorithm_t algorithm, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size) {
    const OPTION& option = _cmdline->value();
    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    openssl_hash dgst;
    hash_context_t* hash_handle = nullptr;

    ansi_string bs;

    const char* alg = advisor->nameof_md(algorithm);
    size_t digest_size = 0;

    __try2 {
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2 {
            ret = dgst.open(&hash_handle, algorithm, key_data, key_size);
            if (errorcode_t::success == ret) {
                binary_t hashed;
                dgst.init(hash_handle);
                ret = dgst.update(hash_handle, data, size);
                if (errorcode_t::success == ret) {
                    ret = dgst.finalize(hash_handle, hashed);
                    digest_size = hashed.size();
                    if (errorcode_t::success == ret) {
                        if (option.verbose) {
                            test_case_notimecheck notimecheck(_test_case);

                            _logger->dump(hashed);
                        }
                    }
                }
                dgst.close(hash_handle);
            }
        }
        __finally2 {}
    }
    __finally2 {
        const char* alg = advisor->nameof_md(algorithm);
        _test_case.test(ret, __FUNCTION__, "digest algmrithm %d (%s) digest (%i, %i)", algorithm, alg ? alg : "unknown", digest_size, digest_size << 3);
    }
}

return_t test_hash_routine(hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text) {
    const OPTION& option = _cmdline->value();
    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    openssl_hash dgst;
    hash_context_t* hash_handle = nullptr;

    ansi_string bs;

    const char* alg = advisor->nameof_md(algorithm);
    size_t digest_size = 0;

    __try2 {
        ret = dgst.open(&hash_handle, algorithm, &key[0], key.size());
        if (errorcode_t::success == ret) {
            binary_t hashed;
            dgst.init(hash_handle);
            ret = dgst.update(hash_handle, &data[0], data.size());
            if (errorcode_t::success == ret) {
                ret = dgst.finalize(hash_handle, hashed);
                digest_size = hashed.size();
                if (errorcode_t::success == ret) {
                    if (option.verbose) {
                        test_case_notimecheck notimecheck(_test_case);

                        _logger->hdump("hmac", hashed);
                    }

                    if ((hashed.size() == expect.size()) && (0 == memcmp(&hashed[0], &expect[0], expect.size()))) {
                        // do nothing
                    } else {
                        ret = errorcode_t::mismatch;
                    }
                }
            }
            dgst.close(hash_handle);
        }
    }
    __finally2 {
        const char* alg = advisor->nameof_md(algorithm);
        _test_case.test(ret, __FUNCTION__, "digest %s algmrithm %d (%s) digest (%i, %i)", text ? text : "", algorithm, alg ? alg : "unknown", digest_size,
                        digest_size << 3);
    }
    return ret;
}

void do_test_hash_loop(unsigned count_algorithms, hash_algorithm_t* algorithms, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size) {
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_hash_routine(algorithms[index_algorithms], key_data, key_size, data, size);
    }
}

void test_openssl_hash() {
    hash_algorithm_t hash_table[] = {
        hash_algorithm_t::md4,       hash_algorithm_t::md5,       hash_algorithm_t::sha1,         hash_algorithm_t::sha2_224,     hash_algorithm_t::sha2_256,
        hash_algorithm_t::sha2_384,  hash_algorithm_t::sha2_512,  hash_algorithm_t::sha2_512_224, hash_algorithm_t::sha2_512_256, hash_algorithm_t::sha3_224,
        hash_algorithm_t::sha3_256,  hash_algorithm_t::sha3_384,  hash_algorithm_t::sha3_512,     hash_algorithm_t::blake2b_512,  hash_algorithm_t::blake2s_256,
        hash_algorithm_t::ripemd160, hash_algorithm_t::whirlpool,
    };
    hash_algorithm_t hmac_table[] = {
        hash_algorithm_t::md4,
        hash_algorithm_t::md5,
        hash_algorithm_t::sha1,
        hash_algorithm_t::sha2_224,
        hash_algorithm_t::sha2_256,
        hash_algorithm_t::sha2_384,
        hash_algorithm_t::sha2_512,
        hash_algorithm_t::sha2_512_224,
        hash_algorithm_t::sha2_512_256,
        hash_algorithm_t::sha3_224,
        hash_algorithm_t::sha3_256,
        hash_algorithm_t::sha3_384,
        hash_algorithm_t::sha3_512,
        // hash_algorithm_t::shake128,
        // hash_algorithm_t::shake256,
        hash_algorithm_t::blake2b_512,
        hash_algorithm_t::blake2s_256,
        hash_algorithm_t::ripemd160,
        hash_algorithm_t::whirlpool,
    };

    byte_t keydata[32] = {
        'S', 'i', 'm', 'o', 'n', ' ', '&', ' ', 'G', 'a', 'r', 'f', 'u', 'n', 'k', 'e', 'l',
    };
    const char* text = "still a man hears what he wants to hear and disregards the rest";  // the boxer - Simon & Garfunkel

    _test_case.begin("openssl_hash hash");
    do_test_hash_loop(RTL_NUMBER_OF(hash_table), hash_table, nullptr, 0, (byte_t*)text, strlen(text));

    _test_case.begin("openssl_hash hmac");
    do_test_hash_loop(RTL_NUMBER_OF(hmac_table), hmac_table, (byte_t*)keydata, 32, (byte_t*)text, strlen(text));
}
