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

#include <stdio.h>

#include <hotplace/sdk/sdk.hpp>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
typedef struct _OPTION {
    bool dump_keys;

    _OPTION() : dump_keys(false) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION> > _cmdline;

void test_hash_routine(hash_t* hash_object, hash_algorithm_t algorithm, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size) {
    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    hash_context_t* hash_handle = nullptr;

    ansi_string bs;

    const char* alg = advisor->nameof_md(algorithm);
    size_t digest_size = 0;

    __try2 {
        if (nullptr == hash_object || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2 {
            ret = hash_object->open(&hash_handle, algorithm, key_data, key_size);
            if (errorcode_t::success == ret) {
                binary_t hashed;
                hash_object->init(hash_handle);
                ret = hash_object->update(hash_handle, data, size);
                if (errorcode_t::success == ret) {
                    ret = hash_object->finalize(hash_handle, hashed);
                    digest_size = hashed.size();
                    if (errorcode_t::success == ret) {
                        test_case_notimecheck notimecheck(_test_case);

                        basic_stream dump;
                        dump_memory(&hashed[0], hashed.size(), &dump, 16, 0);
                        bs.printf("%s\n", dump.c_str());
                    }
                }
                hash_object->close(hash_handle);
            }
        }
        __finally2 {
            // do nothing
        }
    }
    __finally2 {
        const char* alg = advisor->nameof_md(algorithm);
        _test_case.test(ret, __FUNCTION__, "digest algmrithm %d (%s) digest (%i, %i)", algorithm, alg ? alg : "unknown", digest_size, digest_size << 3);
    }
}

return_t test_hash_routine(hash_t* hash_object, hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text) {
    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    hash_context_t* hash_handle = nullptr;

    ansi_string bs;

    const char* alg = advisor->nameof_md(algorithm);
    size_t digest_size = 0;

    __try2 {
        if (nullptr == hash_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2 {
            ret = hash_object->open(&hash_handle, algorithm, &key[0], key.size());
            if (errorcode_t::success == ret) {
                binary_t hashed;
                hash_object->init(hash_handle);
                ret = hash_object->update(hash_handle, &data[0], data.size());
                if (errorcode_t::success == ret) {
                    ret = hash_object->finalize(hash_handle, hashed);
                    digest_size = hashed.size();
                    if (errorcode_t::success == ret) {
                        test_case_notimecheck notimecheck(_test_case);

                        basic_stream dump;
                        dump_memory(&hashed[0], hashed.size(), &dump, 16, 0);
                        bs.printf("%s\n", dump.c_str());

                        if ((hashed.size() == expect.size()) && (0 == memcmp(&hashed[0], &expect[0], expect.size()))) {
                            // do nothing
                        } else {
                            ret = errorcode_t::mismatch;
                        }
                    }
                }
                hash_object->close(hash_handle);
            }
        }
        __finally2 {
            // do nothing
        }
    }
    __finally2 {
        const char* alg = advisor->nameof_md(algorithm);
        _test_case.test(ret, __FUNCTION__, "digest %s algmrithm %d (%s) digest (%i, %i)", text ? text : "", algorithm, alg ? alg : "unknown", digest_size,
                        digest_size << 3);
    }
    return ret;
}

void test_hash_loop(hash_t* hash_object, unsigned count_algorithms, hash_algorithm_t* algorithms, const byte_t* key_data, unsigned key_size, byte_t* data,
                    size_t size) {
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_hash_routine(hash_object, algorithms[index_algorithms], key_data, key_size, data, size);
    }
}

void test_hmacsha_rfc4231() {
    _test_case.begin("openssl_hash RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005");
    // RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005
    // 4.2 Test Case 1
    // 4.2. Test Case 1
    // Key = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
    // Data = 4869205468657265 ("Hi There")
    // HMAC-SHA-224 = 896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22
    // HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    // HMAC-SHA-384 = afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6
    // HMAC-SHA-512 = 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854

    struct _testvector {
        const char* text;
        const char* key;
        const char* data;
        const char* expect_sha224;
        const char* expect_sha256;
        const char* expect_sha384;
        const char* expect_sha512;
    } testvector[] = {
        {"4.2. Test Case 1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
         "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
        {
            "4.3. Test Case 2",
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        },
        {
            "4.4. Test Case 3",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        },
        {
            "4.4. Test Case 4",
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        },
        {
            "4.4. Test Case 6",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        },
        {
            "4.4. Test Case 6",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b"
            "2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f"
            "726974686d2e",
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        },
    };

    return_t ret = errorcode_t::success;
    openssl_hash openssl_hash;
    binary_t bin_key, bin_data, bin_expect_sha224, bin_expect_sha256, bin_expect_sha384, bin_expect_sha512;
    for (int i = 0; i < sizeof(testvector) / sizeof(testvector[0]); i++) {
        struct _testvector& item = testvector[i];

        base16_decode(item.key, strlen(item.key), bin_key);
        base16_decode(item.data, strlen(item.data), bin_data);
        base16_decode(item.expect_sha224, strlen(item.expect_sha224), bin_expect_sha224);
        base16_decode(item.expect_sha256, strlen(item.expect_sha256), bin_expect_sha256);
        base16_decode(item.expect_sha384, strlen(item.expect_sha384), bin_expect_sha384);
        base16_decode(item.expect_sha512, strlen(item.expect_sha512), bin_expect_sha512);

        test_hash_routine(&openssl_hash, hash_algorithm_t::sha2_224, bin_key, bin_data, bin_expect_sha224, item.text);
        test_hash_routine(&openssl_hash, hash_algorithm_t::sha2_256, bin_key, bin_data, bin_expect_sha256, item.text);
        test_hash_routine(&openssl_hash, hash_algorithm_t::sha2_384, bin_key, bin_data, bin_expect_sha384, item.text);
        test_hash_routine(&openssl_hash, hash_algorithm_t::sha2_512, bin_key, bin_data, bin_expect_sha512, item.text);
    }
}

void test_hash_algorithms() {
    hash_algorithm_t hash_table[] = {
        hash_algorithm_t::md4,          hash_algorithm_t::md5,       hash_algorithm_t::sha1,      hash_algorithm_t::sha2_224,
        hash_algorithm_t::sha2_256,     hash_algorithm_t::sha2_384,  hash_algorithm_t::sha2_512,  hash_algorithm_t::sha2_512_224,
        hash_algorithm_t::sha2_512_256, hash_algorithm_t::sha3_224,  hash_algorithm_t::sha3_256,  hash_algorithm_t::sha3_384,
        hash_algorithm_t::sha3_512,     hash_algorithm_t::shake128,  hash_algorithm_t::shake256,  hash_algorithm_t::blake2b_512,
        hash_algorithm_t::blake2s_256,  hash_algorithm_t::ripemd160, hash_algorithm_t::whirlpool,
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

    openssl_hash openssl_hash;
    byte_t keydata[32] = {
        'S', 'i', 'm', 'o', 'n', ' ', '&', ' ', 'G', 'a', 'r', 'f', 'u', 'n', 'k', 'e', 'l',
    };
    const char* text = "still a man hears what he wants to hear and disregards the rest";  // the boxer - Simon & Garfunkel

    _test_case.begin("openssl_hash hash");
    test_hash_loop(&openssl_hash, RTL_NUMBER_OF(hash_table), hash_table, nullptr, 0, (byte_t*)text, strlen(text));

    _test_case.begin("openssl_hash hmac");
    test_hash_loop(&openssl_hash, RTL_NUMBER_OF(hmac_table), hmac_table, (byte_t*)keydata, 32, (byte_t*)text, strlen(text));
}

return_t compare_binary(binary_t const& lhs, binary_t const& rhs) {
    return_t ret = errorcode_t::success;

    if (lhs != rhs) {
        ret = errorcode_t::mismatch;
    }
    return ret;
}

void test_aes128cbc_mac_routine(binary_t const& key, binary_t const& message, binary_t const& expect) {
    return_t ret = errorcode_t::success;

    openssl_hash hash;
    hash_context_t* handle = nullptr;
    binary_t result;

    ret = hash.open(&handle, crypt_algorithm_t::aes128, crypt_mode_t::cbc, &key[0], key.size());
    if (errorcode_t::success == ret) {
        // Figure 2.3.  Algorithm AES-CMAC
        hash.init(handle);
        hash.update(handle, &message[0], message.size());
        hash.finalize(handle, result);
        hash.close(handle);
        basic_stream bs;
        dump_memory(result, &bs);
        std::cout << "result" << std::endl << bs.c_str() << std::endl;
        // Figure 2.4.  Algorithm Verify_MAC
        ret = compare_binary(expect, result);
    }
    _test_case.test(ret, __FUNCTION__, "cmac test");
}

void test_cmac_rfc4493() {
    _test_case.begin("CMAC (RFC 4493)");

    openssl_hash hash;

    constexpr char constexpr_key[] = "2b7e151628aed2a6abf7158809cf4f3c";

    struct test_vector {
        const char* message;
        const char* result;
    } tests[] = {
        {"", "bb1d6929e95937287fa37d129b756746"},
        {"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
        {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
        {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
         "51f0bebf7e3b9d92fc49741779363cfe"},
    };

    binary_t bin_k1 = base16_decode(constexpr_key);

    for (int i = 0; i < RTL_NUMBER_OF(tests); i++) {
        test_aes128cbc_mac_routine(bin_k1, base16_decode(tests[i].message), base16_decode(tests[i].result));
    }
}

uint32 test_hotp_rfc4226() {
    _test_case.begin("HOTP (RFC 4226)");

    uint32 ret = errorcode_t::success;
    otp_context_t* handle = nullptr;

    hmac_otp hotp;
    std::vector<uint32> output;
    byte_t* key = (byte_t*)"12345678901234567890";  // 20
    ret = hotp.open(&handle, 6, hash_algorithm_t::sha1, key, 20);
    if (errorcode_t::success == ret) {
        uint32 code = 0;
        for (int i = 0; i < 10; i++) {
            hotp.get(handle, code);

            {
                test_case_notimecheck notimecheck(_test_case);
                output.push_back(code);
                std::cout << "counter " << i << " code " << code << std::endl;
            }
        }

        hotp.close(handle);
    }

    uint32 sha1_hotp_result[10] = {
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    };
    if (0 != memcmp(&output[0], &sha1_hotp_result[0], 10 * sizeof(uint32))) {
        ret = errorcode_t::internal_error;
    }

    std::cout << std::endl;

    _test_case.test(ret, __FUNCTION__, "RFC4226 HOTP algoritm sha1 + 10 test vectors tested");

    return ret;
}

typedef struct _TOTP_TEST_DATA {
    hash_algorithm_t algorithm;
    byte_t* key;
    size_t key_size;
    uint32 result[6];
} TOTP_TEST_DATA;
TOTP_TEST_DATA _totp_test_data[] = {
    {hash_algorithm_t::sha1,
     (byte_t*)"12345678901234567890",
     20,
     {
         94287082,
         7081804,
         14050471,
         89005924,
         69279037,
         65353130,
     }}, /* sha1 */
    {hash_algorithm_t::sha2_256,
     (byte_t*)"12345678901234567890123456789012",
     32,
     {
         46119246,
         68084774,
         67062674,
         91819424,
         90698825,
         77737706,
     }}, /* sha256 */
    {hash_algorithm_t::sha2_512,
     (byte_t*)"1234567890123456789012345678901234567890123456789012345678901234",
     64,
     {
         90693936,
         25091201,
         99943326,
         93441116,
         38618901,
         47863826,
     }}, /* sha512 */
};

uint32 test_totp_rfc6238(hash_algorithm_t algorithm) {
    _test_case.begin("TOTP/SHA1 (RFC6238)");

    uint32 ret = errorcode_t::success;
    otp_context_t* handle = nullptr;
    TOTP_TEST_DATA* test_data = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        for (size_t index = 0; index < RTL_NUMBER_OF(_totp_test_data); index++) {
            if (algorithm == _totp_test_data[index].algorithm) {
                test_data = _totp_test_data + index;
                break;
            }
        }
        if (nullptr == test_data) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        time_otp totp;
        std::vector<uint32> output;
        ret = totp.open(&handle, 8, 30, algorithm, test_data->key, test_data->key_size);
        if (errorcode_t::success == ret) {
            uint32 code = 0;
            uint64 counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000LL, 20000000000LL};
            for (int i = 0; i < (int)RTL_NUMBER_OF(counter); i++) {
                totp.get(handle, counter[i], code);
                output.push_back(code);

                {
                    test_case_notimecheck notimecheck(_test_case);
                    std::cout << "counter " << counter[i] << " code " << code << std::endl;
                }
            }
            totp.close(handle);
        }

        if (0 != memcmp(&output[0], test_data->result, 6 * sizeof(uint32))) {
            ret = errorcode_t::internal_error;
        }
    }
    __finally2 {
        const char* alg = advisor->nameof_md(algorithm);
        _test_case.test(ret, __FUNCTION__, "RFC6238 TOTP algorithm %s + 6 test vectors tested", alg ? alg : "");
    }

    return ret;
}

void test_hash_hmac_sign() {
    crypto_key key;
    crypto_keychain keychain;
    constexpr char key_source[] = "000102030405060708090a0b0c0d0e0f";
    // Rhapsody - Emerald Sword
    constexpr char in_source[] = "I crossed the valleys the dust of midlands / To search for the third key to open the gates";
    binary_t bin_key = base16_decode(key_source);
    binary_t bin_in = convert(in_source);

    keychain.add_oct(&key, base16_decode(key_source));
    binary_t result;
    basic_stream bs;

    openssl_hash hash;
    openssl_sign sign;

    // source
    dump_memory(bin_in, &bs);
    std::cout << "source" << std::endl << bs.c_str() << std::endl;

    // openssl_hash hash
    hash_context_t* hash_context = nullptr;
    hash.open(&hash_context, hash_algorithm_t::sha2_256);
    hash.hash(hash_context, &bin_in[0], bin_in.size(), result);
    hash.close(hash_context);

    dump_memory(result, &bs);
    std::cout << "hash" << std::endl << bs.c_str() << std::endl;

    // EVP_Digest (hash)
    unsigned int size = 0;
    result.resize(0);
    EVP_Digest(&bin_in[0], bin_in.size(), &result[0], &size, EVP_sha256(), nullptr);
    result.resize(size);
    EVP_Digest(&bin_in[0], bin_in.size(), &result[0], &size, EVP_sha256(), nullptr);
    dump_memory(result, &bs);
    std::cout << "Digest" << std::endl << bs.c_str() << std::endl;

    // openssl_hash hmac
    hash_context_t* hmac_context = nullptr;
    hash.open(&hmac_context, hash_algorithm_t::sha2_256, &bin_key[0], bin_key.size());
    hash.hash(hmac_context, &bin_in[0], bin_in.size(), result);
    hash.close(hmac_context);

    dump_memory(result, &bs);
    std::cout << "HMAC" << std::endl << bs.c_str() << std::endl;

    // openssl_sign
    sign.sign_digest(key.any(), hash_algorithm_t::sha2_256, bin_key, result);

    dump_memory(result, &bs);
    std::cout << "Sign" << std::endl << bs.c_str() << std::endl;
}

void test_ecdsa(crypto_key* key, uint32 nid, hash_algorithm_t alg, binary_t const& input, binary_t const& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_sign sign;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    switch (alg) {
        case sha2_512_224:
        case sha2_512_256:
            ret = errorcode_t::not_supported;
            break;
        default:
            break;
    }
#endif

    const hint_curve_t* hint = advisor->hintof_curve_nid(nid);
    const char* hashalg = advisor->nameof_md(alg);

    EVP_PKEY* pkey = key->any();
    if (errorcode_t::success == ret) {
        /* check EC_GROUP_new_by_curve_name:unknown group */
        EC_KEY* ec = EC_KEY_new_by_curve_name(nid);

        if (ec) {
            EC_KEY_free(ec);
        } else {
            ret = errorcode_t::not_supported;
            ERR_clear_error();
        }
    }

    if (errorcode_t::success == ret) {
        ret = sign.verify_ecdsa(pkey, alg, input, signature);
        OPTION option = _cmdline->value();  // (*_cmdline).value () is ok

        if (option.dump_keys) {
            test_case_notimecheck notimecheck(_test_case);
            basic_stream bs;
            dump_key(pkey, &bs);
            printf("%s\n", bs.c_str());
            dump_memory(input, &bs);
            printf("input\n%s\n", bs.c_str());
            dump_memory(signature, &bs);
            printf("sig\n%s\n", bs.c_str());
        }
    }

    _test_case.test(ret, __FUNCTION__, "ECDSA %s %s", hint ? hint->name : "", hashalg);
}

void test_ecdsa_testvector(const test_vector_nist_cavp_ecdsa_t* vector, size_t sizeof_vector, int base16) {
    for (int i = 0; i < sizeof_vector; i++) {
        crypto_key key;
        crypto_keychain keychain;

        keychain.add_ec(&key, vector[i].nid, base16_decode(vector[i].x), base16_decode(vector[i].y), base16_decode(vector[i].d));
        binary_t signature;
        binary_t bin_r = base16_decode(vector[i].r);
        binary_t bin_s = base16_decode(vector[i].s);
        signature.insert(signature.end(), bin_r.begin(), bin_r.end());
        signature.insert(signature.end(), bin_s.begin(), bin_s.end());

        binary_t message;
        if (base16) {
            message = base16_decode(vector[i].msg);
        } else {
            message = convert(vector[i].msg);
        }
        test_ecdsa(&key, vector[i].nid, vector[i].alg, message, signature);
    }
}

void test_nist_cavp_ecdsa() {
    _test_case.begin("NIST CAVP ECDSA");
    test_ecdsa_testvector(test_vector_nist_cavp_ecdsa, sizeof_test_vector_nist_cavp_ecdsa, 1);
}

void test_rfc6979_ecdsa() {
    _test_case.begin("RFC6079 ECDSA");
    test_ecdsa_testvector(test_vector_rfc6079, sizeof_test_vector_rfc6079, 0);
}

// Authenticated Encryption with AES-CBC and HMAC-SHA
// AEAD_AES_128_CBC_HMAC_SHA_256
// AEAD_AES_192_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_512

#define MAC_KEY_LEN 16
#define ENC_KEY_LEN 16
#if defined DEBUG
#define dump(var)                                                             \
    {                                                                         \
        dump_memory(var, &bs);                                                \
        printf("%s\n%s\n%s\n", #var, bs.c_str(), base16_encode(var).c_str()); \
    }
#else
#define dump(var)
#endif

// https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
// 2.1.  Encryption
// Appendix A.  CBC Encryption and Decryption
return_t aead_aes_cbc_hmac_sha2(const test_vector_aead_aes_cbc_hmac_sha2_t* vector) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == vector) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* enc_alg = vector->enc_alg;
        const char* mac_alg = vector->mac_alg;
        binary_t k = base16_decode(vector->k);
        binary_t iv = base16_decode(vector->iv);
        binary_t a = base16_decode(vector->a);
        binary_t p = base16_decode(vector->p);
        binary_t mac_key;
        binary_t enc_key;
        binary_t ps;
        binary_t q;
        binary_t s;
        binary_t t;
        binary_t c;
        basic_stream bs;

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digest_size = sizeof_digest(hint_digest);
        digest_size >>= 1;  // truncate

        // 2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
        // 2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
        // 2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
        // 2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32

        if (k.size() < digest_size + keysize) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mac_key.insert(mac_key.end(), &k[0], &k[0] + digest_size);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            enc_key.insert(enc_key.end(), &k[digest_size], &k[digest_size] + keysize);
        }

        /* PS (padding string) .. for PKCS#7 padding */
        uint32 mod = p.size() % blocksize;
        uint32 imod = blocksize - mod;
        ps.insert(ps.end(), imod, imod);

        uint64 aad_len = hton64(a.size() << 3);

        /* P || PS */
        binary_t p1;
        p1.insert(p1.end(), p.begin(), p.end());
        p1.insert(p1.end(), ps.begin(), ps.end());

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, enc_alg, enc_key, iv);
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.encrypt(crypt_handle, p1, q);
        crypt.close(crypt_handle);

        /* S = IV || Q */
        s.insert(s.end(), iv.begin(), iv.end());
        s.insert(s.end(), q.begin(), q.end());
        dump(s);

        _test_case.assert(base16_decode(vector->s) == s, __FUNCTION__, "%s S = IV || CBC-ENC(ENC_KEY, P || PS)", vector->text);

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        hmac(mac_alg, mac_key, content, t);
        t.resize(digest_size);

        _test_case.assert(base16_decode(vector->t) == t, __FUNCTION__, "%s T = MAC(MAC_KEY, A || S || AL)", vector->text);

        /* C = S || T */
        c.insert(c.end(), s.begin(), s.end());
        c.insert(c.end(), t.begin(), t.end());

        {
            test_case_notimecheck notimecheck(_test_case);

            dump(k);
            dump(mac_key);
            dump(enc_key);
            dump(p);
            dump(iv);
            dump(a);
            dump(ps);
            dump(iv);
            dump(q);
            dump(t);
            dump(c);
        }

        _test_case.assert(base16_decode(vector->c) == c, __FUNCTION__, "%s C = S || T", vector->text);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t aes_cbc_hmac_sha2_encrypt(const char* enc_alg, const char* mac_alg, binary_t const& k, binary_t const& iv, binary_t const& a, binary_t const& p,
                                   binary_t& q, binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        q.clear();
        t.clear();

        if (nullptr == enc_alg || nullptr == mac_alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digest_size = sizeof_digest(hint_digest);
        digest_size >>= 1;  // truncate

        binary_t mac_key;
        binary_t enc_key;

        if (k.size() < digest_size + keysize) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mac_key.insert(mac_key.end(), &k[0], &k[0] + digest_size);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            enc_key.insert(enc_key.end(), &k[digest_size], &k[digest_size] + keysize);
        }

        binary_t ps;
        binary_t s;

        uint32 mod = p.size() % blocksize;
        uint32 imod = blocksize - mod;
        ps.insert(ps.end(), imod, imod);

        uint64 aad_len = hton64(a.size() << 3);

        /* P || PS */
        binary_t p1;
        p1.insert(p1.end(), p.begin(), p.end());
        p1.insert(p1.end(), ps.begin(), ps.end());

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, enc_alg, enc_key, iv);
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.encrypt(crypt_handle, p1, q);
        crypt.close(crypt_handle);

        /* S = IV || Q */
        s.insert(s.end(), iv.begin(), iv.end());
        s.insert(s.end(), q.begin(), q.end());

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        hmac(mac_alg, mac_key, content, t);  // t := tag
        t.resize(digest_size);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t aes_cbc_hmac_sha2_decrypt(const char* enc_alg, const char* mac_alg, binary_t const& k, binary_t const& iv, binary_t const& a, binary_t const& q,
                                   binary_t& p, binary_t const& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        p.clear();

        if (nullptr == enc_alg || nullptr == mac_alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 ivsize = sizeof_iv(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digest_size = sizeof_digest(hint_digest);
        digest_size >>= 1;  // truncate

        binary_t mac_key;
        binary_t enc_key;

        if (k.size() < digest_size + keysize) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mac_key.insert(mac_key.end(), &k[0], &k[0] + digest_size);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            enc_key.insert(enc_key.end(), &k[digest_size], &k[digest_size] + keysize);
        }

        binary_t ps;

        uint32 mod = p.size() % blocksize;
        uint32 imod = blocksize - mod;
        ps.insert(ps.end(), imod, imod);

        uint64 aad_len = hton64(a.size() << 3);

        /* P || PS */
        binary_t p1;
        p1.insert(p1.end(), p.begin(), p.end());
        p1.insert(p1.end(), ps.begin(), ps.end());

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, enc_alg, enc_key, iv);
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.decrypt(crypt_handle, q, p);
        crypt.close(crypt_handle);

        /* S = IV || Q */
        // s.insert(s.end(), iv.begin(), iv.end());
        // s.insert(s.end(), q.begin(), q.end());

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        binary_t tag;
        hmac(mac_alg, mac_key, content, tag);  // t := tag
        tag.resize(digest_size);
        if (t != tag) {
            ret = errorcode_t::error_verify;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void test_aead_aes_cbc_hmac_sha2() {
    _test_case.begin("Authenticated Encryption with AES-CBC and HMAC-SHA");

    return_t ret = errorcode_t::success;
    basic_stream bs;
    for (int i = 0; i < sizeof_test_vector_aead_aes_cbc_hmac_sha2; i++) {
        const test_vector_aead_aes_cbc_hmac_sha2_t* vector = test_vector_aead_aes_cbc_hmac_sha2 + i;
        aead_aes_cbc_hmac_sha2(vector);
        binary_t s;
        binary_t t;
        ret = aes_cbc_hmac_sha2_encrypt(vector->enc_alg, vector->mac_alg, base16_decode(vector->k), base16_decode(vector->iv), base16_decode(vector->a),
                                        base16_decode(vector->p), s, t);
        _test_case.test(ret, __FUNCTION__, "encrypt %s", vector->text);
        binary_t p;
        ret =
            aes_cbc_hmac_sha2_decrypt(vector->enc_alg, vector->mac_alg, base16_decode(vector->k), base16_decode(vector->iv), base16_decode(vector->a), s, p, t);
        _test_case.test(ret, __FUNCTION__, "decrypt %s", vector->text);
    }
}

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt);

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-dump", "dump keys", [&](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional();
    (*_cmdline).parse(argc, argv);

    OPTION& option = _cmdline->value();
    std::cout << "option.dump_keys " << (option.dump_keys ? 1 : 0) << std::endl;

    __try2 {
        openssl_startup();
        openssl_thread_setup();

        test_hash_algorithms();

        test_hmacsha_rfc4231();
        test_cmac_rfc4493();

        test_hotp_rfc4226();

        test_totp_rfc6238(hash_algorithm_t::sha1);
        test_totp_rfc6238(hash_algorithm_t::sha2_256);
        test_totp_rfc6238(hash_algorithm_t::sha2_512);

        test_hash_hmac_sign();

        test_nist_cavp_ecdsa();
        test_rfc6979_ecdsa();

        test_aead_aes_cbc_hmac_sha2();
    }
    __finally2 {
        openssl_thread_cleanup();
        openssl_cleanup();
    }

    _test_case.report(5);

    return _test_case.result();
}
