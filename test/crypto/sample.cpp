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

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;

void validate_openssl_crypt() {
    _test_case.begin("CAVP block cipher - AES");

    basic_stream bs;
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    for (int i = 0; i < sizeof_test_vector_nist_cavp_blockcipher; i++) {
        const test_vector_nist_cavp_blockcipher_t* vector = test_vector_nist_cavp_blockcipher + i;
        binary_t ciphertext;
        binary_t plaintext;
        crypt.open(&handle, vector->alg, base16_decode(vector->key), base16_decode(vector->iv));
        // EVP_CIPHER_CTX_set_padding(ctx, 0);
        crypt.set(handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.encrypt(handle, base16_decode(vector->plaintext), ciphertext);
        crypt.decrypt(handle, base16_decode(vector->ciphertext), plaintext);
        crypt.close(handle);
        dump_memory(ciphertext, &bs);
        printf("Ciphertext\n%s\n", bs.c_str());
        dump_memory(plaintext, &bs);
        printf("Plaintext\n%s\n", bs.c_str());
        _test_case.assert(base16_decode(vector->ciphertext) == ciphertext, __FUNCTION__, "%s - encrypt", vector->desc);
        _test_case.assert(base16_decode(vector->plaintext) == plaintext, __FUNCTION__, "%s - decrypt", vector->desc);
    }
}

void test_crypt_routine(crypt_t* crypt_object, crypt_algorithm_t algorithm, crypt_mode_t mode, unsigned key_size, const byte_t* key_data, unsigned iv_size,
                        const byte_t* iv_data, byte_t* data, size_t size, byte_t* aad_source = nullptr, unsigned aad_size = 0) {
    _test_case.reset_time();

    return_t ret = errorcode_t::success;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypt_context_t* crypt_handle = nullptr;

    binary_t encrypted;
    binary_t decrypted;

    basic_stream bs;

    binary_t aad;
    binary_t tag;

    __try2 {
        _test_case.reset_time();

        if (nullptr == crypt_object || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2 {
            ret = crypt_object->open(&crypt_handle, algorithm, mode, key_data, key_size, iv_data, iv_size);
            if (errorcode_t::success == ret) {
                size_t crypt_key_size = 0;
                size_t crypt_iv_size = 0;
                crypt_object->query(crypt_handle, 1, crypt_key_size);
                crypt_object->query(crypt_handle, 2, crypt_iv_size);

                if (nullptr == aad_source) {
                    if ((crypt_mode_t::gcm == mode) || (crypt_mode_t::ccm == mode)) {
                        openssl_prng rand;
                        rand.random(aad, 32);
                    }
                } else {
                    aad.insert(aad.end(), aad_source, aad_source + aad_size);

                    std::cout << "aad" << std::endl;
                    dump_memory(&aad[0], aad.size(), &bs);
                    std::cout << bs.c_str() << std::endl;
                }

                ret = crypt_object->encrypt2(crypt_handle, data, size, encrypted, &aad, &tag);
                if (errorcode_t::success == ret) {
                    ret = crypt_object->decrypt2(crypt_handle, &encrypted[0], encrypted.size(), decrypted, &aad, &tag);
                    if (errorcode_t::success == ret) {
                        {
                            test_case_notimecheck notimecheck(_test_case);

                            std::cout << "encrypted" << std::endl;
                            dump_memory(&encrypted[0], encrypted.size(), &bs);
                            std::cout << bs.c_str() << std::endl;

                            std::cout << "decrypted" << std::endl;
                            dump_memory(&decrypted[0], decrypted.size(), &bs);
                            std::cout << bs.c_str() << std::endl;
                        }

                        if (size != decrypted.size()) {
                            ret = errorcode_t::internal_error;
                        } else if (memcmp(data, &decrypted[0], size)) {
                            ret = errorcode_t::internal_error;
                        }
                    }
                }
            }
        }
        __finally2 { crypt_object->close(crypt_handle); }
    }
    __finally2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        const char* alg = advisor->nameof_cipher(algorithm, mode);
        _test_case.test(ret, __FUNCTION__, "encrypt+decrypt algmrithm %d mode %d (%s)", algorithm, mode, alg ? alg : "unknown");
    }
}

void test_crypto_loop(crypt_t* crypt_object, unsigned count_algorithms, crypt_algorithm_t* algorithms, crypt_mode_t mode, unsigned key_size,
                      const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size) {
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        test_crypt_routine(crypt_object, algorithms[index_algorithms], mode, key_size, key_data, iv_size, iv_data, data, size);
    }  // foreach algorithm
}

void test_crypt_algorithms(uint32 cooltime, uint32 unitsize) {
    console_color concolor;

    ossl_set_cooltime(cooltime);
    ossl_set_unitsize(unitsize);

    std::cout << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::white) << "cooltime " << ossl_get_cooltime() << " unitsize "
              << ossl_get_unitsize() << std::endl;
    std::cout << concolor.turnoff();

    crypt_algorithm_t algorithm_table[] = {
        crypt_algorithm_t::aes128,      crypt_algorithm_t::aes192,      crypt_algorithm_t::aes256,   crypt_algorithm_t::aria128,
        crypt_algorithm_t::aria192,     crypt_algorithm_t::aria256,     crypt_algorithm_t::blowfish, crypt_algorithm_t::camellia128,
        crypt_algorithm_t::camellia192, crypt_algorithm_t::camellia256, crypt_algorithm_t::cast,     crypt_algorithm_t::idea,
        crypt_algorithm_t::rc2,         crypt_algorithm_t::rc5,         crypt_algorithm_t::seed,     crypt_algorithm_t::sm4,
    };
    crypt_algorithm_t cfbx_algorithm_table[] = {
        crypt_algorithm_t::aes128,  crypt_algorithm_t::aes192,      crypt_algorithm_t::aes256,      crypt_algorithm_t::aria128,     crypt_algorithm_t::aria192,
        crypt_algorithm_t::aria256, crypt_algorithm_t::camellia128, crypt_algorithm_t::camellia192, crypt_algorithm_t::camellia256,
    };
    crypt_algorithm_t ctr_algorithm_table[] = {
        crypt_algorithm_t::aes128,  crypt_algorithm_t::aes192,      crypt_algorithm_t::aes256,      crypt_algorithm_t::aria128,     crypt_algorithm_t::aria192,
        crypt_algorithm_t::aria256, crypt_algorithm_t::camellia128, crypt_algorithm_t::camellia192, crypt_algorithm_t::camellia256, crypt_algorithm_t::sm4,
    };
    crypt_algorithm_t gcm_algorithm_table[] = {
        crypt_algorithm_t::aes128,  crypt_algorithm_t::aes192,  crypt_algorithm_t::aes256,
        crypt_algorithm_t::aria128, crypt_algorithm_t::aria192, crypt_algorithm_t::aria256,
    };

    openssl_crypt openssl_crypt;
    byte_t keydata[32] = {
        'S', 'i', 'm', 'o', 'n', ' ', '&', ' ', 'G', 'a', 'r', 'f', 'u', 'n', 'k', 'e', 'l',
    };
    byte_t iv[32] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    };
    constexpr char constexpr_text[] = "still a man hears what he wants to hear and disregards the rest";  // the boxer - Simon & Garfunkel

    __try2 {
        std::string condition = format("[test condition cooltime %i unitsize %i]", ossl_get_cooltime(), ossl_get_unitsize());

        _test_case.begin("openssl_crypt crypt_mode_t::cbc %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::cbc, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                         strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::cfb %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::cfb, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                         strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::cfb1 %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb1, 16, keydata, 16, iv,
                         (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::cfb8 %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb8, 16, keydata, 16, iv,
                         (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ofb %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::ofb, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                         strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ecb %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::ecb, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                         strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ctr %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(ctr_algorithm_table), ctr_algorithm_table, crypt_mode_t::ctr, 16, keydata, 16, iv,
                         (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::gcm %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(gcm_algorithm_table), gcm_algorithm_table, crypt_mode_t::gcm, 16, keydata, 16, iv,
                         (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ccm %s", condition.c_str());
        test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(gcm_algorithm_table), gcm_algorithm_table, crypt_mode_t::ccm, 16, keydata, 16, iv,
                         (byte_t*)constexpr_text, strlen(constexpr_text));
    }
    __finally2 {
        // do nothing
    }
}

void test_chacha20_rfc8439_2_4() {
    // RFC 7539 2.4.  The ChaCha20 Encryption Algorithm
    // RFC 8439 2.4.  The ChaCha20 Encryption Algorithm
    _test_case.begin("RFC 7539/8439 2.4 The ChaCha20 Encryption Algorithm");
    openssl_crypt openssl_crypt;
    binary_t key;
    binary_t nonce;
    binary_t block;
    basic_stream bs;
    uint32 i = 0;

    key.resize(32);
    for (i = 0; i < 32; i++) {
        key[i] = i;
    }

    // openssl EVP_chacha20 specific counter+nonce
    byte_t nonce_source[12] = {
        0, 0, 0, 0, 0, 0, 0, 0x4a,
    };
    openssl_chacha20_iv(nonce, 1, nonce_source, 12);

    const char* block_source = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    block << block_source;

    {
        test_case_notimecheck notimecheck(_test_case);

        dump_memory(key, &bs);
        printf("key\n%s\n", bs.c_str());
        dump_memory(nonce, &bs);
        printf("nonce w counter 1\n%s\n", bs.c_str());
        dump_memory(block, &bs);
        printf("block\n%s\n", bs.c_str());
    }

    // Ciphertext Sunscreen:
    // 000  6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81  n.5.%h..A..(..i.
    // 016  e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b  .~z..C`..'......
    // 032  f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57  ..e.RG3..Y=..b.W
    // 048  16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8  .9.$.QR..S.5..a.
    // 064  07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e  ....P.jaV....".^
    // 080  52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36  R.QM.........y76
    // 096  5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42  Z...t.[......x^B
    // 112  87 4d                                            .M

    test_crypt_routine(&openssl_crypt, crypt_algorithm_t::chacha20, crypt_mode_t::stream_cipher, key.size(), &key[0], nonce.size(), &nonce[0], &block[0],
                       block.size());
}

void test_chacha20poly1305_rfc8439_2_8() {
    // RFC 7539 2.8.  AEAD Construction
    // RFC 8439 2.8.  AEAD Construction
    _test_case.begin("RFC 7539/8439 2.8 AEAD Construction");
    openssl_crypt openssl_crypt;
    binary_t key;
    binary_t nonce;
    binary_t block;
    binary_t aad;
    basic_stream bs;
    uint32 i = 0;

    // Key:
    // 000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
    // 016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................
    for (i = 0x80; i <= 0x9f; i++) {
        key.push_back(i);
    }

    // counter (LE)
    // 32-bit fixed-common part:
    // 000  07 00 00 00                                      ....
    //
    // IV:
    // 000  40 41 42 43 44 45 46 47                          @ABCDEFG
    byte_t nonce_source[] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    openssl_chacha20_iv(nonce, 7, nonce_source, RTL_NUMBER_OF(nonce_source));

    // AAD:
    // 000  50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7              PQRS........
    const char* aad_source = "50515253c0c1c2c3c4c5c6c7";
    aad = base16_decode(aad_source);

    {
        test_case_notimecheck notimecheck(_test_case);

        dump_memory(key, &bs);
        printf("key\n%s\n", bs.c_str());
        dump_memory(nonce, &bs);
        printf("nonce w counter 1\n%s\n", bs.c_str());
    }

    const char* block_source = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    block << block_source;

    // Ciphertext:
    // 000  d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2  ...4d.`.{...S.~.
    // 016  a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6  ...Q)n......6.b.
    // 032  3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b  =..^..g....i..r.
    // 048  1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36  .q.....)....~.;6
    // 064  92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58  ....-w......(..X
    // 080  fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc  ..$...u.U...H1..
    // 096  3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b  ?....Kz..v.e...K
    // 112  61 16                                            a.

    test_crypt_routine(&openssl_crypt, crypt_algorithm_t::chacha20, crypt_mode_t::stream_aead, key.size(), &key[0], nonce.size(), &nonce[0], &block[0],
                       block.size(), &aad[0], aad.size());
}

void test_random() {
    _test_case.begin("random");

    return_t ret = errorcode_t::success;
    uint32 value = 0;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        value = random.rand32();
        printf("rand %08x\n", (int)value);
    }

    _test_case.test(ret, __FUNCTION__, "random loop %i times", times);
}

return_t compare_binary(binary_t const& lhs, binary_t const& rhs) {
    return_t ret = errorcode_t::success;

    if (lhs != rhs) {
        ret = errorcode_t::mismatch;
    }
    return ret;
}

void test_keywrap_routine(crypt_algorithm_t alg, binary_t const& kek, binary_t const& key, binary_t const& expect, const char* msg) {
    return_t ret = errorcode_t::success;

    _test_case.reset_time();

    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    byte_t iv[8];
    int i = 0;

    for (i = 0; i < 8; i++) {
        iv[i] = 0xa6;
    }
    binary_t out_kw, out_kuw;
    basic_stream bs;

    ret = crypt.open(&handle, alg, crypt_mode_t::wrap, &kek[0], kek.size(), iv, RTL_NUMBER_OF(iv));
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, &key[0], key.size(), out_kw);

        {
            test_case_notimecheck notimecheck(_test_case);

            crypto_advisor* advisor = crypto_advisor::get_instance();
            const char* nameof_alg = advisor->nameof_cipher(alg, crypt_mode_t::wrap);
            printf("alg %s\n", nameof_alg);

            dump_memory(kek, &bs);
            printf("kek\n%.*s\n", (int)bs.size(), bs.c_str());
            dump_memory(key, &bs);
            printf("key\n%.*s\n", (int)bs.size(), bs.c_str());
            dump_memory(out_kw, &bs);
            printf("keywrap\n%.*s\n", (int)bs.size(), bs.c_str());

            ret = compare_binary(out_kw, expect);
        }

        crypt.decrypt(handle, &out_kw[0], out_kw.size(), out_kuw);

        {
            test_case_notimecheck notimecheck(_test_case);

            dump_memory(&out_kuw[0], out_kuw.size(), &bs);
            printf("key\n%.*s\n", (int)bs.size(), bs.c_str());
        }

        crypt.close(handle);
    }
    _test_case.test(ret, __FUNCTION__, msg ? msg : "");
}

void test_keywrap_rfc3394() {
    _test_case.begin("keywrap");

    for (int i = 0; i < sizeof_test_vector_rfc3394; i++) {
        const test_vector_rfc3394_t* vector = test_vector_rfc3394 + i;
        test_keywrap_routine(vector->alg, base16_decode(vector->kek), base16_decode(vector->key), base16_decode(vector->expect), vector->message);
    }
}

// Authenticated Encryption with AES-CBC and HMAC-SHA
// AEAD_AES_128_CBC_HMAC_SHA_256
// AEAD_AES_192_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_512

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

#if defined DEBUG
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
#endif

        _test_case.assert(base16_decode(vector->c) == c, __FUNCTION__, "%s C = S || T", vector->text);
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

int main() {
    set_trace_option(trace_option_t::trace_bt);

    __try2 {
        openssl_startup();
        openssl_thread_setup();

        validate_openssl_crypt();  // validate wrapper class openssl_crypt

        test_crypt_algorithms(10, 4096);  // performance (for large stream encryption performance, just check error occurrence)
        test_crypt_algorithms(0, 0);      // speed

        test_random();

        test_keywrap_rfc3394();

        test_chacha20_rfc8439_2_4();
        test_chacha20poly1305_rfc8439_2_8();

        test_aead_aes_cbc_hmac_sha2();
    }
    __finally2 {
        openssl_thread_cleanup();
        openssl_cleanup();
    }

    _test_case.report(5);
    std::cout << "openssl 3 deprected bf, idea, seed" << std::endl;
    return _test_case.result();
}
