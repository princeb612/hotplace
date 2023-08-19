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


void test_crypt_routine (crypt_interface* crypt_object, crypt_symmetric_t algorithm, crypt_mode_t mode, unsigned key_size,
                         const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size)
{
    return_t ret = errorcode_t::success;

    crypto_advisor* advisor = crypto_advisor::get_instance ();
    crypt_context_t* crypt_handle = nullptr;

    binary_t encrypted;
    binary_t decrypted;

    buffer_stream dump;

    const char* alg = advisor->nameof_cipher (algorithm, mode);
    std::string display = format ("%s (alg %i mode %i)", alg ? alg : "", algorithm, mode);
    binary_t aad;
    binary_t tag;

    __try2
    {
        _test_case.start ();

        if (nullptr == crypt_object || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        __try2
        {
            ret = crypt_object->open (&crypt_handle, algorithm, mode, key_data, key_size, iv_data, iv_size);
            if (errorcode_t::success == ret) {
                dump.printf ("crypt engine %d algorithm %d %s",
                             crypt_object->get_type (), algorithm, display.c_str ());
                std::cout << dump.c_str () << std::endl;
                dump.flush ();

                size_t crypt_key_size = 0;
                size_t crypt_iv_size = 0;
                crypt_object->query (crypt_handle, 1, crypt_key_size);
                crypt_object->query (crypt_handle, 2, crypt_iv_size);
                dump.printf ("key size %zi iv size %zi", crypt_key_size, crypt_iv_size);
                std::cout << dump.c_str () << std::endl;
                dump.flush ();

                if (crypt_mode_t::gcm == mode) {
                    openssl_prng rand;
                    rand.random (aad, 32);
                    std::cout << "aad" << std::endl;
                    dump_memory (&aad[0], aad.size (), &dump);
                    std::cout << dump.c_str () << std::endl;
                    dump.flush ();
                }

                ret = crypt_object->encrypt2 (crypt_handle, data, size, encrypted, &aad, &tag);
                if (errorcode_t::success == ret) {
                    ret = crypt_object->decrypt2 (crypt_handle, &encrypted[0], encrypted.size (), decrypted, &aad, &tag);
                    if (errorcode_t::success == ret) {
                        std::cout << "sourcce" << std::endl;
                        dump_memory (data, size, &dump, 16, 0);
                        std::cout << dump.c_str () << std::endl;

                        std::cout << "encrypted" << std::endl;
                        dump_memory (&encrypted[0], encrypted.size (), &dump, 16, 0);
                        std::cout << dump.c_str () << std::endl;

                        std::cout << "decrypted" << std::endl;
                        dump_memory (&decrypted[0], decrypted.size (), &dump, 16, 0);
                        std::cout << dump.c_str () << std::endl;

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
        _test_case.test (ret, __FUNCTION__, display.c_str ());
    }
}

void test_crypt (crypt_interface* crypt_object, unsigned count_algorithms, crypt_symmetric_t* algorithms, crypt_mode_t mode, unsigned key_size,
                 const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size)
{
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_crypt_routine (crypt_object, algorithms [index_algorithms], mode, key_size, key_data, iv_size, iv_data, data, size);
    } // foreach algorithm
}

void test_hash_routine (hash_interface* hash_object, hash_algorithm_t algorithm, unsigned key_size, const byte_t* key_data,
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
        test_hash_routine (hash_object, algorithms [index_algorithms], key_size, key_data, data, size);
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

void test ()
{

    byte_t pKey[32] = { 'S', 'i', 'm', 'o', 'n', ' ', '&', ' ', 'G', 'a', 'r', 'f', 'u', 'n', 'k', 'e', 'l', };
    byte_t iv[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, };
    const char* szText = "still a man hears what he wants to hear and disregards the rest"; // the boxer - Simon & Garfunkel

    crypt_symmetric_t algorithm_table [] = {
        crypt_symmetric_t::aes128,
        crypt_symmetric_t::aes192,
        crypt_symmetric_t::aes256,
        crypt_symmetric_t::blowfish,
        crypt_symmetric_t::aria128,
        crypt_symmetric_t::aria192,
        crypt_symmetric_t::aria256,
        crypt_symmetric_t::camellia128,
        crypt_symmetric_t::camellia192,
        crypt_symmetric_t::camellia256,
        crypt_symmetric_t::idea,
        crypt_symmetric_t::seed,
    };
    crypt_symmetric_t cfbx_algorithm_table [] = {
        crypt_symmetric_t::aes128,
        crypt_symmetric_t::aes192,
        crypt_symmetric_t::aes256,
        crypt_symmetric_t::aria128,
        crypt_symmetric_t::aria192,
        crypt_symmetric_t::aria256,
        crypt_symmetric_t::camellia128,
        crypt_symmetric_t::camellia192,
        crypt_symmetric_t::camellia256,
    };
    crypt_symmetric_t ctr_algorithm_table [] = {
        crypt_symmetric_t::aes128,
        crypt_symmetric_t::aes192,
        crypt_symmetric_t::aes256,
        crypt_symmetric_t::aria128,
        crypt_symmetric_t::aria192,
        crypt_symmetric_t::aria256,
    };

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

    openssl_crypt openssl_crypt;
    openssl_hash openssl_hash;

    __try2
    {
        std::string condition = format ("[test condition cooltime %zi unitsize %zi]", ossl_get_cooltime (), ossl_get_unitsize ());

        _test_case.begin ("openssl_crypt crypt_mode_t::cbc %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::cbc, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::cfb, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb1 %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb1, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::cfb8 %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb8, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::ofb %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::ofb, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::ecb %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (algorithm_table), algorithm_table, crypt_mode_t::ecb, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::ctr %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (ctr_algorithm_table), ctr_algorithm_table, crypt_mode_t::ctr, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));
        _test_case.begin ("openssl_crypt crypt_mode_t::gcm %s", condition.c_str ());
        test_crypt (&openssl_crypt, RTL_NUMBER_OF (ctr_algorithm_table), ctr_algorithm_table, crypt_mode_t::gcm, 16, pKey, 16, iv, (byte_t*) szText,
                    strlen (szText));

        _test_case.begin ("openssl_hash hash");
        test_hash (&openssl_hash, RTL_NUMBER_OF (hash_table), hash_table, 0, nullptr, (byte_t*) szText, strlen (szText));

        _test_case.begin ("openssl_hash hmac");
        test_hash (&openssl_hash, RTL_NUMBER_OF (hmac_table), hmac_table, 32, (byte_t*) pKey, (byte_t*) szText, strlen (szText));

        _test_case.begin ("random");
        test_random ();

        _test_case.begin ("keywrap");
        test_keywrap ();
    }
    __finally2
    {
        // do nothing
    }
}

int main ()
{
    openssl_startup ();
    openssl_thread_setup ();

    console_color col;

    struct {
        uint32 cooltime;
        uint32 unitsize;
    } _test_condition [] = {
        { 0, 0, },
        { 10, 4096, },
    };

    for (unsigned i = 0; i < sizeof (_test_condition) / sizeof (_test_condition [0]); i++) {
        ossl_set_cooltime (_test_condition[i].cooltime);
        ossl_set_unitsize (_test_condition[i].unitsize);

        std::cout << col.set_style (console_style_t::bold).set_fgcolor (console_color_t::white).turnon ()
                  << "cooltime " << ossl_get_cooltime ()
                  << "unitsize " << ossl_get_unitsize ()
                  << std::endl;
        test ();
    }

    openssl_thread_cleanup ();
    openssl_cleanup ();

    _test_case.report ();
    std::cout << "openssl 3 deprected bf, idea, seed" << std::endl;
    return _test_case.result ();
}
