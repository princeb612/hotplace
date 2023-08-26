/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;

void test_crypt_routine (crypt_t* crypt_object, crypt_algorithm_t algorithm, crypt_mode_t mode, unsigned key_size,
                         const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size)
{
    _test_case.reset_time ();

    return_t ret = errorcode_t::success;

    crypto_advisor* advisor = crypto_advisor::get_instance ();
    crypt_context_t* crypt_handle = nullptr;

    binary_t encrypted;
    binary_t decrypted;

    buffer_stream bs;

    binary_t aad;
    binary_t tag;

    __try2
    {
        _test_case.reset_time ();

        if (nullptr == crypt_object || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        __try2
        {
            ret = crypt_object->open (&crypt_handle, algorithm, mode, key_data, key_size, iv_data, iv_size);
            if (errorcode_t::success == ret) {
                size_t crypt_key_size = 0;
                size_t crypt_iv_size = 0;
                crypt_object->query (crypt_handle, 1, crypt_key_size);
                crypt_object->query (crypt_handle, 2, crypt_iv_size);

                if (crypt_mode_t::gcm == mode) {
                    openssl_prng rand;
                    rand.random (aad, 32);
                }

                ret = crypt_object->encrypt2 (crypt_handle, data, size, encrypted, &aad, &tag);
                if (errorcode_t::success == ret) {
                    ret = crypt_object->decrypt2 (crypt_handle, &encrypted[0], encrypted.size (), decrypted, &aad, &tag);
                    if (errorcode_t::success == ret) {
                        _test_case.pause_time ();

                        std::cout << "encrypted" << std::endl;
                        dump_memory (&encrypted[0], encrypted.size (), &bs);
                        std::cout << bs.c_str () << std::endl;

                        std::cout << "decrypted" << std::endl;
                        dump_memory (&decrypted[0], decrypted.size (), &bs);
                        std::cout << bs.c_str () << std::endl;

                        _test_case.resume_time ();

                        if (size != decrypted.size ()) {
                            ret = errorcode_t::internal_error;
                        } else if (memcmp (data, &decrypted[0], size)) {
                            ret = errorcode_t::internal_error;
                        }
                    }
                }
            }
        }
        __finally2
        {
            crypt_object->close (crypt_handle);
        }
    }
    __finally2
    {
        const char* alg = advisor->nameof_cipher (algorithm, mode);
        _test_case.test (ret, __FUNCTION__, "encrypt+dectypt algmrithm %d mode %d (%s)", algorithm, mode, alg ? alg : "unknown");
    }
}

void test_crypt (crypt_t* crypt_object, unsigned count_algorithms, crypt_algorithm_t* algorithms, crypt_mode_t mode, unsigned key_size,
                 const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size)
{
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_crypt_routine (crypt_object, algorithms [index_algorithms], mode, key_size, key_data, iv_size, iv_data, data, size);
    } // foreach algorithm
}

void test_crypt_algorithms ()
{
    crypt_algorithm_t algorithm_table [] = {
        crypt_algorithm_t::aes128,
        crypt_algorithm_t::aes192,
        crypt_algorithm_t::aes256,
        crypt_algorithm_t::aria128,
        crypt_algorithm_t::aria192,
        crypt_algorithm_t::aria256,
        crypt_algorithm_t::blowfish,
        crypt_algorithm_t::cast,
        crypt_algorithm_t::camellia128,
        crypt_algorithm_t::camellia192,
        crypt_algorithm_t::camellia256,
        crypt_algorithm_t::idea,
        crypt_algorithm_t::rc2,
        crypt_algorithm_t::rc5,
        crypt_algorithm_t::seed,
    };
    crypt_algorithm_t cfbx_algorithm_table [] = {
        crypt_algorithm_t::aes128,
        crypt_algorithm_t::aes192,
        crypt_algorithm_t::aes256,
        crypt_algorithm_t::aria128,
        crypt_algorithm_t::aria192,
        crypt_algorithm_t::aria256,
        crypt_algorithm_t::camellia128,
        crypt_algorithm_t::camellia192,
        crypt_algorithm_t::camellia256,
    };
    crypt_algorithm_t ctr_algorithm_table [] = {
        crypt_algorithm_t::aes128,
        crypt_algorithm_t::aes192,
        crypt_algorithm_t::aes256,
        crypt_algorithm_t::aria128,
        crypt_algorithm_t::aria192,
        crypt_algorithm_t::aria256,
        crypt_algorithm_t::sm4,
    };
    crypt_algorithm_t gcm_algorithm_table [] = {
        crypt_algorithm_t::aes128,
        crypt_algorithm_t::aes192,
        crypt_algorithm_t::aes256,
        crypt_algorithm_t::aria128,
        crypt_algorithm_t::aria192,
        crypt_algorithm_t::aria256,
    };

    openssl_crypt openssl_crypt;
    byte_t keydata[32] = { 'S', 'i', 'm', 'o', 'n', ' ', '&', ' ', 'G', 'a', 'r', 'f', 'u', 'n', 'k', 'e', 'l', };
    byte_t iv[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, };
    const char* text = "still a man hears what he wants to hear and disregards the rest"; // the boxer - Simon & Garfunkel

    __try2
    {
        std::string condition = format ("[test condition cooltime %zi unitsize %zi]", ossl_get_cooltime (), ossl_get_unitsize ());

        _test_case.begin ("openssl_crypt crypt_mode_t::cbc %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::cbc, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::cfb, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb1 %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb1, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb8 %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb8, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::ofb %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::ofb, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::ecb %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::ecb, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::ctr %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (ctr_algorithm_table), ctr_algorithm_table, crypt_mode_t::ctr, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
        _test_case.begin ("openssl_crypt crypt_mode_t::gcm %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (gcm_algorithm_table), gcm_algorithm_table, crypt_mode_t::gcm, 16, keydata, 16, iv, (byte_t*) text,
                    strlen (text));
    }
    __finally2
    {
        // do nothing
    }
}

void test_crypt ()
{
    console_color col;

    struct {
        uint32 cooltime;
        uint32 unitsize;
    } _test_condition [] = {
        { 10, 4096, },  // performance (for large stream encryption performance, just check error occurrence)
        { 0, 0, },      // speed
    };

    for (unsigned i = 0; i < sizeof (_test_condition) / sizeof (_test_condition [0]); i++) {
        ossl_set_cooltime (_test_condition[i].cooltime);
        ossl_set_unitsize (_test_condition[i].unitsize);

        std::cout   << col.turnon ().set_style (console_style_t::bold).set_fgcolor (console_color_t::white)
                    << "cooltime " << ossl_get_cooltime () << " unitsize " << ossl_get_unitsize ()
                    << col.turnoff ()
                    << std::endl;
        test_crypt_algorithms ();
    }
}

void test_hash_routine (hash_t* hash_object, hash_algorithm_t algorithm,
                        const byte_t* key_data, unsigned key_size, byte_t* data, size_t size)
{
    _test_case.reset_time ();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    hash_context_t* hash_handle = nullptr;

    ansi_string bs;

    const char* alg = advisor->nameof_md (algorithm);

    __try2
    {
        if (nullptr == hash_object || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        __try2
        {
            int ret = hash_object->open (&hash_handle, algorithm, key_data, key_size);
            if (errorcode_t::success == ret) {
                binary_t hashed;
                hash_object->init (hash_handle);
                ret = hash_object->update (hash_handle, data, size);
                if (errorcode_t::success == ret) {
                    ret = hash_object->finalize (hash_handle, hashed);
                    if (errorcode_t::success == ret) {
                        _test_case.pause_time ();

                        buffer_stream dump;
                        dump_memory (&hashed[0], hashed.size (), &dump, 16, 0);
                        bs.printf ("%s\n",  dump.c_str ());

                        _test_case.resume_time ();
                    }
                }
                hash_object->close (hash_handle);
            }

            _test_case.pause_time ();
            printf ("%s", bs.c_str ());
            _test_case.resume_time ();
        }
        __finally2
        {
            // do nothing
        }
    }
    __finally2
    {
        const char* alg = advisor->nameof_md (algorithm);
        _test_case.test (ret, __FUNCTION__, "digest algmrithm %d (%s)", algorithm, alg ? alg : "unknown");
    }
}

return_t test_hash_routine (hash_t* hash_object, hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text)
{
    _test_case.reset_time ();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    hash_context_t* hash_handle = nullptr;

    ansi_string bs;

    const char* alg = advisor->nameof_md (algorithm);

    __try2
    {
        if (nullptr == hash_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        __try2
        {
            int ret = hash_object->open (&hash_handle, algorithm, &key[0], key.size ());
            if (errorcode_t::success == ret) {
                binary_t hashed;
                hash_object->init (hash_handle);
                ret = hash_object->update (hash_handle, &data[0], data.size ());
                if (errorcode_t::success == ret) {
                    ret = hash_object->finalize (hash_handle, hashed);
                    if (errorcode_t::success == ret) {
                        _test_case.pause_time ();

                        buffer_stream dump;
                        dump_memory (&hashed[0], hashed.size (), &dump, 16, 0);
                        bs.printf ("%s\n",  dump.c_str ());

                        if ((hashed.size () == expect.size ()) && (0 == memcmp (&hashed[0], &expect[0], expect.size ()))) {
                            // do nothing
                        } else {
                            ret = errorcode_t::mismatch;
                        }

                        _test_case.resume_time ();
                    }
                }
                hash_object->close (hash_handle);
            }
        }
        __finally2
        {
            // do nothing
        }
    }
    __finally2
    {
        const char* alg = advisor->nameof_md (algorithm);
        _test_case.test (ret, __FUNCTION__, "digest+dump %s algmrithm %d (%s)", text ? text : "", algorithm, alg ? alg : "unknown");
    }
    return ret;
}

void test_hash (hash_t* hash_object, unsigned count_algorithms, hash_algorithm_t* algorithms,
                const byte_t* key_data, unsigned key_size, byte_t* data, size_t size)
{
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_hash_routine (hash_object, algorithms [index_algorithms], key_data, key_size, data, size);
    }
}

void test_rfc4231_testcase ()
{
    _test_case.begin ("openssl_hash RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005");
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
    } testvector [] = {
        {
            "4.2. Test Case 1",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        },
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
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        },
        {
            "4.4. Test Case 6",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        },
    };

    return_t ret = errorcode_t::success;
    openssl_hash openssl_hash;
    binary_t bin_key, bin_data, bin_expect_sha224, bin_expect_sha256, bin_expect_sha384, bin_expect_sha512;
    for (int i = 0; i < sizeof (testvector) / sizeof (testvector[0]); i++) {
        struct _testvector& item = testvector[i];

        base16_decode (item.key, strlen (item.key), bin_key);
        base16_decode (item.data, strlen (item.data), bin_data);
        base16_decode (item.expect_sha224, strlen (item.expect_sha224), bin_expect_sha224);
        base16_decode (item.expect_sha256, strlen (item.expect_sha256), bin_expect_sha256);
        base16_decode (item.expect_sha384, strlen (item.expect_sha384), bin_expect_sha384);
        base16_decode (item.expect_sha512, strlen (item.expect_sha512), bin_expect_sha512);

        test_hash_routine (&openssl_hash, hash_algorithm_t::sha2_224, bin_key, bin_data, bin_expect_sha224, item.text);
        test_hash_routine (&openssl_hash, hash_algorithm_t::sha2_256, bin_key, bin_data, bin_expect_sha256, item.text);
        test_hash_routine (&openssl_hash, hash_algorithm_t::sha2_384, bin_key, bin_data, bin_expect_sha384, item.text);
        test_hash_routine (&openssl_hash, hash_algorithm_t::sha2_512, bin_key, bin_data, bin_expect_sha512, item.text);
    }
}

void test_hash_algorithms ()
{
    hash_algorithm_t hash_table [] =
    {
        hash_algorithm_t::md4,
        hash_algorithm_t::md5,
        hash_algorithm_t::sha1,
        hash_algorithm_t::sha2_224,
        hash_algorithm_t::sha2_256,
        hash_algorithm_t::sha2_384,
        hash_algorithm_t::sha2_512,
        hash_algorithm_t::sha3_224,
        hash_algorithm_t::sha3_256,
        hash_algorithm_t::sha3_384,
        hash_algorithm_t::sha3_512,
        hash_algorithm_t::shake128,
        hash_algorithm_t::shake256,
        hash_algorithm_t::blake2b_512,
        hash_algorithm_t::blake2s_256,
        hash_algorithm_t::ripemd160,
        hash_algorithm_t::whirlpool,
    };
    hash_algorithm_t hmac_table [] =
    {
        hash_algorithm_t::md4,
        hash_algorithm_t::md5,
        hash_algorithm_t::sha1,
        hash_algorithm_t::sha2_224,
        hash_algorithm_t::sha2_256,
        hash_algorithm_t::sha2_384,
        hash_algorithm_t::sha2_512,
        hash_algorithm_t::sha3_224,
        hash_algorithm_t::sha3_256,
        hash_algorithm_t::sha3_384,
        hash_algorithm_t::sha3_512,
        //hash_algorithm_t::shake128,
        //hash_algorithm_t::shake256,
        hash_algorithm_t::blake2b_512,
        hash_algorithm_t::blake2s_256,
        hash_algorithm_t::ripemd160,
        hash_algorithm_t::whirlpool,
    };

    openssl_hash openssl_hash;
    byte_t keydata[32] = { 'S', 'i', 'm', 'o', 'n', ' ', '&', ' ', 'G', 'a', 'r', 'f', 'u', 'n', 'k', 'e', 'l', };
    const char* text = "still a man hears what he wants to hear and disregards the rest"; // the boxer - Simon & Garfunkel

    _test_case.begin ("openssl_hash hash");
    test_hash (&openssl_hash, RTL_NUMBER_OF (hash_table), hash_table, nullptr, 0, (byte_t*) text, strlen (text));

    _test_case.begin ("openssl_hash hmac");
    test_hash (&openssl_hash, RTL_NUMBER_OF (hmac_table), hmac_table, (byte_t*) keydata, 32, (byte_t*) text, strlen (text));
}

void test_digest ()
{
    test_rfc4231_testcase ();
    test_hash_algorithms ();
}

void test_random ()
{
    _test_case.begin ("random");

    return_t ret = errorcode_t::success;
    uint32 value = 0;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        value = random.rand32 ();
        printf ("rand %08x\n", (int) value);
    }

    _test_case.test (ret, __FUNCTION__, "random loop %i times", times);
}

void test_keywrap_routine (crypt_algorithm_t alg, byte_t* key, size_t key_size, byte_t* kek, size_t kek_size,
                           byte_t* expect, size_t expect_size,
                           const char* msg)
{

    _test_case.reset_time ();
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    byte_t iv [8];
    int i = 0;

    for (i = 0; i < 8; i++) {
        iv [i] = 0xa6;
    }
    binary_t out_kw, out_kuw;
    buffer_stream bs;
    bool compare = false;

    crypt.open (&handle, alg, crypt_mode_t::wrap, key, key_size, iv, RTL_NUMBER_OF (iv));
    crypt.encrypt (handle, kek, kek_size, out_kw);

    _test_case.pause_time ();

    dump_memory (&out_kw[0], out_kw.size (), &bs);
    printf ("%.*s\n", (int) bs.size (), bs.c_str ());

    _test_case.resume_time ();

    if ((out_kw.size () == expect_size) && (0 == memcmp (&out_kw[0], expect, out_kw.size ()))) {
        compare = true;
    }

    crypt.decrypt (handle, &out_kw[0], out_kw.size (), out_kuw);

    _test_case.pause_time ();

    dump_memory (&out_kuw[0], out_kuw.size (), &bs);
    printf ("%.*s\n", (int) bs.size (), bs.c_str ());

    _test_case.resume_time ();

    crypt.close (handle);
    _test_case.test (compare ? errorcode_t::success : errorcode_t::mismatch, __FUNCTION__, msg ? msg : "");
}

void test_keywrap ()
{
    _test_case.begin ("keywrap");

    // RFC 3394 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F
    // Key Data 00112233445566778899AABBCCDDEEFF
    // Ciphertext:  1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5
    std::string string_kek1 = "000102030405060708090A0B0C0D0E0F";
    std::string string_key1 = "00112233445566778899AABBCCDDEEFF";
    std::string string_kw1 = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5";
    binary_t kek1, key1, kw1;

    base16_decode (string_kek1, kek1);
    base16_decode (string_key1, key1);
    base16_decode (string_kw1, kw1);

    test_keywrap_routine (crypt_algorithm_t::aes128, &kek1[0], kek1.size (), &key1[0], key1.size (), &kw1[0], kw1.size (),
                          "RFC 3394 4.1 Wrap 128 bits of Key Data with a 128-bit KEK");

    // RFC 3394 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F1011121314151617
    // Key Data 00112233445566778899AABBCCDDEEFF
    // Ciphertext: 96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D
    std::string string_kek2 = "000102030405060708090A0B0C0D0E0F1011121314151617";
    std::string string_key2 = "00112233445566778899AABBCCDDEEFF";
    std::string string_kw2 = "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D";
    binary_t kek2, key2, kw2;
    base16_decode (string_kek2, kek2);
    base16_decode (string_key2, key2);
    base16_decode (string_kw2, kw2);

    test_keywrap_routine (crypt_algorithm_t::aes192, &kek2[0], kek2.size (), &key2[0], key2.size (), &kw2[0], kw2.size (),
                          "RFC 3394 4.2 Wrap 128 bits of Key Data with a 192-bit KEK");

    // RFC 3394 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // Key Data 00112233445566778899AABBCCDDEEFF
    // Ciphertext: 64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7
    std::string string_kek3 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    std::string string_key3 = "00112233445566778899AABBCCDDEEFF";
    std::string string_kw3 = "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7";
    binary_t kek3, key3, kw3;
    base16_decode (string_kek3, kek3);
    base16_decode (string_key3, key3);
    base16_decode (string_kw3, kw3);

    test_keywrap_routine (crypt_algorithm_t::aes256, &kek3[0], kek3.size (), &key3[0], key3.size (), &kw3[0], kw3.size (),
                          "RFC 3394 4.3 Wrap 128 bits of Key Data with a 256-bit KEK");

    // RFC 3394 4.4 Wrap 192 bits of Key Data with a 192-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F1011121314151617
    // Key Data 00112233445566778899AABBCCDDEEFF0001020304050607
    // Ciphertext: 031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2
    std::string string_kek4 = "000102030405060708090A0B0C0D0E0F1011121314151617";
    std::string string_key4 = "00112233445566778899AABBCCDDEEFF0001020304050607";
    std::string string_kw4 = "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2";
    binary_t kek4, key4, kw4;
    base16_decode (string_kek4, kek4);
    base16_decode (string_key4, key4);
    base16_decode (string_kw4, kw4);

    test_keywrap_routine (crypt_algorithm_t::aes192, &kek4[0], kek4.size (), &key4[0], key4.size (), &kw4[0], kw4.size (),
                          "RFC 3394 4.4 Wrap 192 bits of Key Data with a 192-bit KEK");

    // RFC 3394 4.5 Wrap 192 bits of Key Data with a 256-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // Key Data 00112233445566778899AABBCCDDEEFF0001020304050607
    // Ciphertext: A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1
    std::string string_kek5 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    std::string string_key5 = "00112233445566778899AABBCCDDEEFF0001020304050607";
    std::string string_kw5 = "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1";
    binary_t kek5, key5, kw5;
    base16_decode (string_kek5, kek5);
    base16_decode (string_key5, key5);
    base16_decode (string_kw5, kw5);

    test_keywrap_routine (crypt_algorithm_t::aes256, &kek5[0], kek5.size (), &key5[0], key5.size (), &kw5[0], kw5.size (),
                          "RFC 3394 4.5 Wrap 192 bits of Key Data with a 256-bit KEK");

    // RFC 3394 4.6 Wrap 256 bits of Key Data with a 256-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // Key Data 00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
    // Ciphertext: 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
    std::string string_kek6 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    std::string string_key6 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    std::string string_kw6 = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";
    binary_t kek6, key6, kw6;
    base16_decode (string_kek6, kek6);
    base16_decode (string_key6, key6);
    base16_decode (string_kw6, kw6);

    test_keywrap_routine (crypt_algorithm_t::aes256, &kek6[0], kek6.size (), &key6[0], key6.size (), &kw6[0], kw6.size (),
                          "RFC 3394 4.6 Wrap 256 bits of Key Data with a 256-bit KEK");
}

uint32 test_hotp ()
{
    uint32 ret = errorcode_t::success;
    otp_context_t* handle = nullptr;

    _test_case.begin ("hmac_otp (RFC4226)");

    hmac_otp hotp;
    std::vector<uint32> output;
    byte_t* key = (byte_t*) "12345678901234567890"; // 20
    ret = hotp.open (&handle, 6, hash_algorithm_t::sha1, key, 20);
    if (errorcode_t::success == ret) {
        uint32 code = 0;
        for (int i = 0; i < 10; i++) {
            hotp.get (handle, code);

            _test_case.pause_time ();

            output.push_back (code);

            std::cout << "counter " << i << " code " << code << std::endl;

            _test_case.resume_time ();
        }

        hotp.close (handle);
    }

    uint32 sha1_hotp_result[10] = { 755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489, };
    if (0 != memcmp (&output[0], &sha1_hotp_result[0], 10 * sizeof (uint32))) {
        ret = errorcode_t::internal_error;
    }

    std::cout << std::endl;

    _test_case.test (ret, __FUNCTION__, "RFC4226 HOTP algoritm sha1 + 10 test vectors tested");

    return ret;
}

typedef struct _TOTP_TEST_DATA {
    hash_algorithm_t algorithm;
    byte_t* key;
    size_t key_size;
    uint32 result[6];
} TOTP_TEST_DATA;
TOTP_TEST_DATA _totp_test_data[] =
{
    { hash_algorithm_t::sha1,    (byte_t*) "12345678901234567890", 20, { 94287082, 7081804, 14050471, 89005924, 69279037, 65353130, } },                                                /* sha1 */
    { hash_algorithm_t::sha2_256, (byte_t*) "12345678901234567890123456789012", 32, { 46119246, 68084774, 67062674,  91819424,  90698825, 77737706, } },                                /* sha256 */
    { hash_algorithm_t::sha2_512, (byte_t*) "1234567890123456789012345678901234567890123456789012345678901234", 64, { 90693936, 25091201, 99943326, 93441116, 38618901, 47863826, } },  /* sha512 */
};

uint32 test_totp (hash_algorithm_t algorithm)
{
    uint32 ret = errorcode_t::success;
    otp_context_t* handle = nullptr;
    TOTP_TEST_DATA* test_data = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    _test_case.begin ("time_otp (RFC6238)");

    __try2
    {
        for (size_t index = 0; index < RTL_NUMBER_OF (_totp_test_data); index++) {
            if (algorithm == _totp_test_data[index].algorithm) {
                test_data = _totp_test_data + index;
                break;
            }
        }
        if (nullptr == test_data) {
            ret = errorcode_t::not_supported;
            __leave2_trace (ret);
        }

        time_otp totp;
        std::vector<uint32> output;
        ret = totp.open (&handle, 8, 30, algorithm, test_data->key, test_data->key_size);
        if (errorcode_t::success == ret) {
            uint32 code = 0;
            uint64 counter[] = { 59, 1111111109, 1111111111, 1234567890, 2000000000LL, 20000000000LL };
            for (int i = 0; i < (int) RTL_NUMBER_OF (counter); i++) {
                totp.get (handle, counter[i], code);
                output.push_back (code);

                _test_case.pause_time ();

                std::cout << "counter " << counter[i] << " code " << code << std::endl;

                _test_case.resume_time ();
            }
            totp.close (handle);
        }

        if (0 != memcmp (&output[0], test_data->result, 6 * sizeof (uint32))) {
            ret = errorcode_t::internal_error;
        }
    }
    __finally2
    {
        const char* alg = advisor->nameof_md (algorithm);
        _test_case.test (ret, __FUNCTION__, "RFC6238 TOTP algorithm %s + 6 test vectors tested", alg ? alg : "");
    }

    return ret;
}

void test_otp ()
{
    _test_case.begin ("hmac_otp");
    test_hotp ();

    _test_case.begin ("time_otp/SHA1 (RFC6238)");
    test_totp (hash_algorithm_t::sha1);

    _test_case.begin ("time_otp/SHA256 (RFC6238)");
    test_totp (hash_algorithm_t::sha2_256);

    _test_case.begin ("time_otp/SHA512 (RFC6238)");
    test_totp (hash_algorithm_t::sha2_512);
}

int main ()
{
    __try2
    {
        openssl_startup ();
        openssl_thread_setup ();

        test_crypt ();

        test_digest ();

        test_random ();

        test_keywrap ();

        test_otp ();
    }
    __finally2
    {
        openssl_thread_cleanup ();
        openssl_cleanup ();
    }

    _test_case.report ();
    _test_case.time_report (5);
    std::cout << "openssl 3 deprected bf, idea, seed" << std::endl;
    return _test_case.result ();
}
