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
using namespace hotplace::test;

test_case _test_case;

typedef struct _CRYPT_TABLE {
    int algorithm;
    int mode;
    const char* name;
} CRYPT_TABLE;
CRYPT_TABLE _crypt_table[] =
{
    {
        crypt_symmetric_t::seed,
        crypt_mode_t::cbc,
        "-seed",
    },
    {
        crypt_symmetric_t::seed,
        crypt_mode_t::cbc,
        "-seed-cbc",
    },
    {
        crypt_symmetric_t::seed,
        crypt_mode_t::cfb,
        "-seed-cfb",
    },
    {
        crypt_symmetric_t::seed,
        crypt_mode_t::ofb,
        "-seed-ofb",
    },
    {
        crypt_symmetric_t::seed,
        crypt_mode_t::ecb,
        "-seed-ecb",
    },

    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::cbc,
        "-aes128",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::cbc,
        "-aes-128-cbc",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::cfb,
        "-aes-128-cfb",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::ofb,
        "-aes-128-ofb",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::ecb,
        "-aes-128-ecb",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::gcm,
        "-aes-128-gcm",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::cfb1,
        "-aes-128-cfb1",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::cfb8,
        "-aes-128-cfb8",
    },
    {
        crypt_symmetric_t::aes128,
        crypt_mode_t::ctr,
        "-aes-128-ctr",
    },

    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::cbc,
        "-aes192",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::cbc,
        "-aes-192-cbc",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::cfb,
        "-aes-192-cfb",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::ofb,
        "-aes-192-ofb",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::ecb,
        "-aes-192-ecb",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::gcm,
        "-aes-192-gcm",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::cfb1,
        "-aes-192-cfb1",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::cfb8,
        "-aes-192-cfb8",
    },
    {
        crypt_symmetric_t::aes192,
        crypt_mode_t::ctr,
        "-aes-192-ctr",
    },

    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::cbc,
        "-aes256",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::cbc,
        "-aes-256-cbc",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::cfb,
        "-aes-256-cfb",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::ofb,
        "-aes-256-ofb",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::ecb,
        "-aes-256-ecb",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::gcm,
        "-aes-256-gcm",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::cfb1,
        "-aes-256-cfb1",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::cfb8,
        "-aes-256-cfb8",
    },
    {
        crypt_symmetric_t::aes256,
        crypt_mode_t::ctr,
        "-aes-256-ctr",
    },

    {
        crypt_symmetric_t::blowfish,
        crypt_mode_t::cbc,
        "-bf",
    },
    {
        crypt_symmetric_t::blowfish,
        crypt_mode_t::cbc,
        "-bf-cbc",
    },
    {
        crypt_symmetric_t::blowfish,
        crypt_mode_t::cfb,
        "-bf-cfb",
    },
    {
        crypt_symmetric_t::blowfish,
        crypt_mode_t::ofb,
        "-bf-ofb",
    },
    {
        crypt_symmetric_t::blowfish,
        crypt_mode_t::ecb,
        "-bf-ecb",
    },

    {
        crypt_symmetric_t::idea,
        crypt_mode_t::cbc,
        "-idea",
    },
    {
        crypt_symmetric_t::idea,
        crypt_mode_t::cbc,
        "-idea-cbc",
    },
    {
        crypt_symmetric_t::idea,
        crypt_mode_t::cfb,
        "-idea-cfb",
    },
    {
        crypt_symmetric_t::idea,
        crypt_mode_t::ofb,
        "-idea-ofb",
    },
    {
        crypt_symmetric_t::idea,
        crypt_mode_t::ecb,
        "-idea-ecb",
    },

    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::cbc,
        "-aria128",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::cbc,
        "-aria-128-cbc",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::cfb,
        "-aria-128-cfb",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::ofb,
        "-aria-128-ofb",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::ecb,
        "-aria-128-ecb",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::gcm,
        "-aria-128-gcm",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::cfb1,
        "-aria-128-cfb1",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::cfb8,
        "-aria-128-cfb8",
    },
    {
        crypt_symmetric_t::aria128,
        crypt_mode_t::ctr,
        "-aria-128-ctr",
    },

    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::cbc,
        "-aria192",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::cbc,
        "-aria-192-cbc",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::cfb,
        "-aria-192-cfb",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::ofb,
        "-aria-192-ofb",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::ecb,
        "-aria-192-ecb",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::gcm,
        "-aria-192-gcm",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::cfb1,
        "-aria-192-cfb1",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::cfb8,
        "-aria-192-cfb8",
    },
    {
        crypt_symmetric_t::aria192,
        crypt_mode_t::ctr,
        "-aria-192-ctr",
    },

    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::cbc,
        "-aria256",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::cbc,
        "-aria-256-cbc",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::cfb,
        "-aria-256-cfb",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::ofb,
        "-aria-256-ofb",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::ecb,
        "-aria-256-ecb",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::gcm,
        "-aria-256-gcm",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::cfb1,
        "-aria-256-cfb1",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::cfb8,
        "-aria-256-cfb8",
    },
    {
        crypt_symmetric_t::aria256,
        crypt_mode_t::ctr,
        "-aria-256-ctr",
    },

    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::cbc,
        "-camellia128",
    },
    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::cbc,
        "-camellia-128-cbc",
    },
    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::cfb,
        "-camellia-128-cfb",
    },
    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::ofb,
        "-camellia-128-ofb",
    },
    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::ecb,
        "-camellia-128-ecb",
    },
    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::cfb1,
        "-camellia-128-cfb1",
    },
    {
        crypt_symmetric_t::camellia128,
        crypt_mode_t::cfb8,
        "-camellia-128-cfb8",
    },

    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::cbc,
        "-camellia192",
    },
    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::cbc,
        "-camellia-192-cbc",
    },
    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::cfb,
        "-camellia-192-cfb",
    },
    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::ofb,
        "-camellia-192-ofb",
    },
    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::ecb,
        "-camellia-192-ecb",
    },
    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::cfb1,
        "-camellia-192-cfb1",
    },
    {
        crypt_symmetric_t::camellia192,
        crypt_mode_t::cfb8,
        "-camellia-192-cfb8",
    },

    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::cbc,
        "-camellia256",
    },
    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::cbc,
        "-camellia-256-cbc",
    },
    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::cfb,
        "-camellia-256-cfb",
    },
    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::ofb,
        "-camellia-256-ofb",
    },
    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::ecb,
        "-camellia-256-ecb",
    },
    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::cfb1,
        "-camellia-256-cfb1",
    },
    {
        crypt_symmetric_t::camellia256,
        crypt_mode_t::cfb8,
        "-camellia-256-cfb8",
    },
};

typedef struct _HASH_ALGORITHM_TABLE {
    int alg;
    const char* name;
} HASH_ALGORITHM_TABLE;
HASH_ALGORITHM_TABLE hash_algorithm_table[] =
{
    {
        hash_algorithm_t::md4,
        "md4",
    },
    {
        hash_algorithm_t::md5,
        "md5",
    },
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    {
        HASH_ALGORITHM_SHA,
        "sha",
    },
#endif
    {
        hash_algorithm_t::sha1,
        "sha1",
    },
    {
        hash_algorithm_t::ripemd160,
        "ripemd160",
    },
    {
        hash_algorithm_t::sha2_224,
        "sha224",
    },
    {
        hash_algorithm_t::sha2_256,
        "sha256",
    },
    {
        hash_algorithm_t::sha2_384,
        "sha384",
    },
    {
        hash_algorithm_t::sha2_512,
        "sha512",
    },
    {
        hash_algorithm_t::whirlpool,
        "whirlpool",
    },
    {
        hash_algorithm_t::sha3_224,
        "sha3-224"
    },
    {
        hash_algorithm_t::sha3_256,
        "sha3-256"
    },
    {
        hash_algorithm_t::sha3_384,
        "sha3-384"
    },
    {
        hash_algorithm_t::sha3_512,
        "sha3-512"
    },
    {
        hash_algorithm_t::shake128,
        "shake128"
    },
    {
        hash_algorithm_t::shake256,
        "shake256"
    },
};

void test_crypt1 (crypt_interface* crypt_object, crypt_symmetric_t algorithm, crypt_mode_t mode, unsigned key_size,
                  const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size)
{
    return_t ret = errorcode_t::success;

    crypto_advisor* advisor = crypto_advisor::get_instance ();
    crypt_context_t* crypt_handle = nullptr;
    byte_t* data_encrypted = nullptr;
    byte_t* data_decrypted = nullptr;

    buffer_stream dump;

    const char* alg = advisor->nameof_cipher (algorithm, mode);
    std::string display = format ("%s (alg %i mode %i)", alg ? alg : "", algorithm, mode);

    __try2
    {
        if (nullptr == crypt_object || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        __try2
        {
            ret = crypt_object->open (&crypt_handle, algorithm, mode, key_data, key_size, iv_data, iv_size);
            if (errorcode_t::success == ret) {
                std::cout   << "crypt engine " << crypt_object->get_type ()
                            << " algorithm " << algorithm << " " << display.c_str ()
                            << std::endl;
                size_t crypt_key_size = 0;
                size_t crypt_iv_size = 0;
                crypt_object->query (crypt_handle, 1, crypt_key_size);
                crypt_object->query (crypt_handle, 2, crypt_iv_size);
                std::cout << "key size " << crypt_key_size << " iv size " << crypt_iv_size << std::endl;

                size_t dwEncrypt = 0;
                size_t dwPlain = 0;
                ret = crypt_object->encrypt (crypt_handle, (byte_t*) data, size, &data_encrypted, &dwEncrypt);
                if (errorcode_t::success == ret) {
                    ret = crypt_object->decrypt (crypt_handle, data_encrypted, dwEncrypt, &data_decrypted, &dwPlain);
                    if (errorcode_t::success == ret) {
                        dump_memory (data, size, &dump, 16, 0);
                        printf ("%s\n", dump.c_str ());
                        dump_memory (data_encrypted, dwEncrypt, &dump, 16, 0);
                        std::cout << dump.c_str () << std::endl;
                        dump_memory (data_decrypted, dwPlain, &dump, 16, 0);
                        printf ("%s\n", dump.c_str ());

                        if (size != dwPlain) {
                            ret = ERROR_INTERNAL_ERROR;
                        } else if (memcmp (data, data_decrypted, size)) {
                            ret = ERROR_INTERNAL_ERROR;
                        }

#if PERFORMANCE_TEST_OPENSSL
                        {
                            Process process;
                            std::string stream;
                            std::string command = format ("echo %.*s|openssl enc -e %s -K 41686E6C61625365637265744B657900 -iv 01020304 | "
                                                          "xxd -c 256 -p", size, (char*) data, name);
                            process.run (command.c_str (), stream);

                            std::string enc ((char*) data_encrypted, dwEncrypt);
                            std::string tohex;
                            tohex = string2hex (enc, 0);

                            std::cout << "!openssl = " << command.c_str () << std::endl;
                            std::cout << ">openssl = " << stream.c_str (); /* including new-line */
                            std::cout << ">routine = " << tohex.c_str () << std::endl;

                        }
#endif
                    } else {
                        __leave2_trace (ret);
                    }
                } else {
                    __leave2_trace (ret);
                }
            }
            /* else do nothing - algorithm and mode not supported */
        }
        __finally2
        {
            crypt_object->free_data (data_encrypted);
            crypt_object->free_data (data_decrypted);
            if (nullptr != crypt_handle) {
                crypt_object->close (crypt_handle);
            }
        }
    }
    __finally2
    {
        _test_case.test (ret, __FUNCTION__, display.c_str ());
    }
}

void test_crypt (crypt_interface* crypt_object, unsigned count_algorithms, crypt_symmetric_t* algorithms, crypt_mode_t mode, unsigned key_size,
                 const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size)
{
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_crypt1 (crypt_object, algorithms [index_algorithms], mode, key_size, key_data, iv_size, iv_data, data, size);
    } // foreach algorithm
}

void test_hash1 (hash_interface* hash_object, hash_algorithm_t algorithm, unsigned key_size, const byte_t* key_data,
                 byte_t* data, size_t size)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    hash_context_t* hash_handle = nullptr;
    byte_t* pHashed = nullptr;

    buffer_stream bs;

    const char* alg = advisor->nameof_md (algorithm);
    std::string display = format ("%s (alg %i)", alg ? alg : "", algorithm);

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
                bs.printf ("hash_engine %d algorithm %d %s\n", hash_object->get_type (), algorithm, display.c_str ());

                hash_object->init (hash_handle);
                size_t dwHashed = 0;
                ret = hash_object->update (hash_handle, data, size);
                if (errorcode_t::success == ret) {
                    ret = hash_object->finalize (hash_handle, &pHashed, &dwHashed);
                    if (errorcode_t::success == ret) {
                        buffer_stream dump;
                        dump_memory (pHashed, dwHashed, &dump, 16, 0);
                        bs.printf ("%s\n",  dump.c_str ());

                        hash_object->free_data (pHashed);
                    }
                }
                hash_object->close (hash_handle);
            }
            printf ("%s", bs.c_str ());
        }
        __finally2
        {
            // do nothing
        }
    }
    __finally2
    {
        _test_case.test (ret, __FUNCTION__, display.c_str ());
    }
}

void test_hash (hash_interface* hash_object, unsigned count_algorithms, hash_algorithm_t* algorithms, unsigned key_size, const byte_t* key_data,
                byte_t* data, size_t size)
{
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_hash1 (hash_object, algorithms [index_algorithms], key_size, key_data, data, size);
    }
}

void test_random ()
{
    return_t ret = errorcode_t::success;
    uint32 value = 0;
    openssl_prng random;
    int i = 0;

    for (i = 0; i < 30; i++) {
        value = random.rand32 ();
        printf ("rand %08x\n", (int) value);
    }

    _test_case.test (ret, __FUNCTION__, "random");
}

void test_keywrap_routine (crypt_symmetric_t alg, byte_t* key, size_t key_size, byte_t* kek, size_t kek_size,
                           byte_t* expect, size_t expect_size,
                           const char* msg)
{
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
    dump_memory (&out_kw[0], out_kw.size (), &bs);
    printf ("%.*s\n", (int) bs.size (), bs.c_str ());
    if ((out_kw.size () == expect_size) && (0 == memcmp (&out_kw[0], expect, out_kw.size ()))) {
        compare = true;
    }
    crypt.decrypt (handle, &out_kw[0], out_kw.size (), out_kuw);
    dump_memory (&out_kuw[0], out_kuw.size (), &bs);
    printf ("%.*s\n", (int) bs.size (), bs.c_str ());
    crypt.close (handle);
    _test_case.test (compare ? errorcode_t::success : errorcode_t::mismatch, __FUNCTION__, msg ? msg : "");
}

void test_keywrap ()
{
    // RFC 3394 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F
    // Key Data 00112233445566778899AABBCCDDEEFF
    // Output:
    // Ciphertext:  1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5
    std::string string_kek1 = "000102030405060708090A0B0C0D0E0F";
    std::string string_key1 = "00112233445566778899AABBCCDDEEFF";
    std::string string_kw1 = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5";
    binary_t kek1, key1, kw1;
    hex2bin h2b;

    h2b.convert (string_kek1, kek1);
    h2b.convert (string_key1, key1);
    h2b.convert (string_kw1, kw1);

    test_keywrap_routine (crypt_symmetric_t::aes128, &kek1[0], kek1.size (), &key1[0], key1.size (), &kw1[0], kw1.size (),
                          "RFC 3394 4.1 Wrap 128 bits of Key Data with a 128-bit KEK");

    // RFC 3394 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F1011121314151617
    // Key Data 00112233445566778899AABBCCDDEEFF
    // Output:
    // Ciphertext: 96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D
    std::string string_kek2 = "000102030405060708090A0B0C0D0E0F1011121314151617";
    std::string string_key2 = "00112233445566778899AABBCCDDEEFF";
    std::string string_kw2 = "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D";
    binary_t kek2, key2, kw2;
    h2b.convert (string_kek2, kek2);
    h2b.convert (string_key2, key2);
    h2b.convert (string_kw2, kw2);

    test_keywrap_routine (crypt_symmetric_t::aes192, &kek2[0], kek2.size (), &key2[0], key2.size (), &kw2[0], kw2.size (),
                          "RFC 3394 4.2 Wrap 128 bits of Key Data with a 192-bit KEK");

    // RFC 3394 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // Key Data 00112233445566778899AABBCCDDEEFF
    // Output:
    // Ciphertext: 64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7
    std::string string_kek3 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    std::string string_key3 = "00112233445566778899AABBCCDDEEFF";
    std::string string_kw3 = "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7";
    binary_t kek3, key3, kw3;
    h2b.convert (string_kek3, kek3);
    h2b.convert (string_key3, key3);
    h2b.convert (string_kw3, kw3);

    test_keywrap_routine (crypt_symmetric_t::aes256, &kek3[0], kek3.size (), &key3[0], key3.size (), &kw3[0], kw3.size (),
                          "RFC 3394 4.3 Wrap 128 bits of Key Data with a 256-bit KEK");

    // RFC 3394 4.4 Wrap 192 bits of Key Data with a 192-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F1011121314151617
    // Key Data 00112233445566778899AABBCCDDEEFF0001020304050607
    // Output:
    // Ciphertext: 031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2
    std::string string_kek4 = "000102030405060708090A0B0C0D0E0F1011121314151617";
    std::string string_key4 = "00112233445566778899AABBCCDDEEFF0001020304050607";
    std::string string_kw4 = "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2";
    binary_t kek4, key4, kw4;
    h2b.convert (string_kek4, kek4);
    h2b.convert (string_key4, key4);
    h2b.convert (string_kw4, kw4);

    test_keywrap_routine (crypt_symmetric_t::aes192, &kek4[0], kek4.size (), &key4[0], key4.size (), &kw4[0], kw4.size (),
                          "RFC 3394 4.4 Wrap 192 bits of Key Data with a 192-bit KEK");

    // RFC 3394 4.5 Wrap 192 bits of Key Data with a 256-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // Key Data 00112233445566778899AABBCCDDEEFF0001020304050607
    // Output:
    // Ciphertext: A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1
    std::string string_kek5 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    std::string string_key5 = "00112233445566778899AABBCCDDEEFF0001020304050607";
    std::string string_kw5 = "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1";
    binary_t kek5, key5, kw5;
    h2b.convert (string_kek5, kek5);
    h2b.convert (string_key5, key5);
    h2b.convert (string_kw5, kw5);

    test_keywrap_routine (crypt_symmetric_t::aes256, &kek5[0], kek5.size (), &key5[0], key5.size (), &kw5[0], kw5.size (),
                          "RFC 3394 4.5 Wrap 192 bits of Key Data with a 256-bit KEK");

    // RFC 3394 4.6 Wrap 256 bits of Key Data with a 256-bit KEK
    // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // Key Data 00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
    // Output:
    // Ciphertext: 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
    std::string string_kek6 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    std::string string_key6 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    std::string string_kw6 = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";
    binary_t kek6, key6, kw6;
    h2b.convert (string_kek6, kek6);
    h2b.convert (string_key6, key6);
    h2b.convert (string_kw6, kw6);

    test_keywrap_routine (crypt_symmetric_t::aes256, &kek6[0], kek6.size (), &key6[0], key6.size (), &kw6[0], kw6.size (),
                          "RFC 3394 4.6 Wrap 256 bits of Key Data with a 256-bit KEK");
}

int main ()
{
#if 0
    ossl_set_cooltime (10);
    ossl_set_unitsize (10);
    cprintf (0, 31, "cooltime %i unitsize %i\n", ossl_get_cooltime (), ossl_get_unitsize ());
#endif

    openssl_startup ();
    openssl_thread_setup ();

#if 0
    ossl_set_cooltime (1);
    ossl_set_ctblksize (16);
#endif

    byte_t pKey[32] = { 'N', 'i', 'n', 'e', 't', 'y', 'N', 'i', 'n', 'e', 'R', 'e', 'd', 'B', 'a', 'l', 'l', 'o', 'o', 'n', };
    byte_t iv[32] = { 0, };
    const char* szText = "still a man hears what he wants to hear and disregards the rest"; // the boxer - Simon & Garfunkel

    crypt_symmetric_t crypt_algorithm[] = {
        crypt_symmetric_t::seed,
        crypt_symmetric_t::aes128,
        crypt_symmetric_t::aes192,
        crypt_symmetric_t::aes256,
        crypt_symmetric_t::blowfish,
        crypt_symmetric_t::idea,
        crypt_symmetric_t::aria128,
        crypt_symmetric_t::aria192,
        crypt_symmetric_t::aria256,
        crypt_symmetric_t::camellia128,
        crypt_symmetric_t::camellia192,
        crypt_symmetric_t::camellia256,
    };
    crypt_symmetric_t crypt_algorithm_ctr[] = {
        crypt_symmetric_t::aes128,
        crypt_symmetric_t::aes192,
        crypt_symmetric_t::aes256,
        crypt_symmetric_t::aria128,
        crypt_symmetric_t::aria192,
        crypt_symmetric_t::aria256,
    };
    hash_algorithm_t hash_algorithm[] = {
        hash_algorithm_t::md4,
        hash_algorithm_t::md5,
        hash_algorithm_t::sha1,
        hash_algorithm_t::sha2_256,
        hash_algorithm_t::sha2_384,
        hash_algorithm_t::sha2_512
    };

    openssl_crypt openssl_crypt;
    openssl_hash openssl_hash;

    __try2
    {
        _test_case.begin ("openssl_crypt crypt_mode_t::cbc");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm), crypt_algorithm, crypt_mode_t::cbc, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm), crypt_algorithm, crypt_mode_t::cfb, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb1");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm), crypt_algorithm, crypt_mode_t::cfb1, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb8");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm), crypt_algorithm, crypt_mode_t::cfb8, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::ofb");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm), crypt_algorithm, crypt_mode_t::ofb, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::ecb");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm), crypt_algorithm, crypt_mode_t::ecb, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::ctr");
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (crypt_algorithm_ctr), crypt_algorithm_ctr, crypt_mode_t::ctr, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));

        _test_case.begin ("openssl_hash");
        test_hash (&openssl_hash, RTL_NUMBER_OF (hash_algorithm), hash_algorithm, 0, nullptr, (byte_t*) szText, strlen (szText));
        test_hash (&openssl_hash, RTL_NUMBER_OF (hash_algorithm), hash_algorithm, 32, (byte_t*) pKey, (byte_t*) szText, strlen (szText));

        _test_case.begin ("openssl_hash SHA-3");
        test_hash1 (&openssl_hash, hash_algorithm_t::sha3_224, 0, nullptr, (byte_t*) "", 0);
        test_hash1 (&openssl_hash, hash_algorithm_t::sha3_256, 0, nullptr, (byte_t*) "", 0);
        test_hash1 (&openssl_hash, hash_algorithm_t::sha3_384, 0, nullptr, (byte_t*) "", 0);
        test_hash1 (&openssl_hash, hash_algorithm_t::sha3_512, 0, nullptr, (byte_t*) "", 0);
        test_hash1 (&openssl_hash, hash_algorithm_t::shake128, 0, nullptr, (byte_t*) "", 0);
        test_hash1 (&openssl_hash, hash_algorithm_t::shake256, 0, nullptr, (byte_t*) "", 0);

        _test_case.begin ("random");
        test_random ();

        _test_case.begin ("keywrap");
        test_keywrap ();
    }
    __finally2
    {
        _test_case.report ();
    }

    openssl_thread_cleanup ();
    openssl_cleanup ();

    _test_case.report ();
    return _test_case.result ();
}
