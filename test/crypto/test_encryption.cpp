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

void validate_openssl_crypt() {
    _test_case.begin("CAVP block cipher - AES");
    const OPTION& option = _cmdline->value();

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

        if (option.verbose) {
            _logger->hdump("Ciphertext", ciphertext);
            _logger->hdump("Plaintext", plaintext);
        }

        _test_case.assert(base16_decode(vector->ciphertext) == ciphertext, __FUNCTION__, "%s - encrypt", vector->desc);
        _test_case.assert(base16_decode(vector->plaintext) == plaintext, __FUNCTION__, "%s - decrypt", vector->desc);
    }
}

void do_test_crypt_routine(crypt_t* crypt_object, crypt_algorithm_t algorithm, crypt_mode_t mode, unsigned key_size, const byte_t* key_data, unsigned iv_size,
                           const byte_t* iv_data, byte_t* data, size_t size, byte_t* aad_source = nullptr, unsigned aad_size = 0) {
    _test_case.reset_time();

    return_t ret = errorcode_t::success;

    const OPTION& option = _cmdline->value();
    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypt_context_t* crypt_handle = nullptr;

    binary_t encrypted;
    binary_t decrypted;

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

                    if (option.verbose) {
                        _logger->hdump("aad", aad);
                    }
                }

                ret = crypt_object->encrypt2(crypt_handle, data, size, encrypted, &aad, &tag);
                if (errorcode_t::success == ret) {
                    ret = crypt_object->decrypt2(crypt_handle, &encrypted[0], encrypted.size(), decrypted, &aad, &tag);
                    if (errorcode_t::success == ret) {
                        if (option.verbose) {
                            test_case_notimecheck notimecheck(_test_case);

                            _logger->hdump("encrypted", encrypted);
                            _logger->hdump("decrypted", decrypted);
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

void do_test_crypto_loop(crypt_t* crypt_object, unsigned count_algorithms, crypt_algorithm_t* algorithms, crypt_mode_t mode, unsigned key_size,
                         const byte_t* key_data, unsigned iv_size, const byte_t* iv_data, byte_t* data, size_t size) {
    for (unsigned index_algorithms = 0; index_algorithms < count_algorithms; index_algorithms++) {
        do_test_crypt_routine(crypt_object, algorithms[index_algorithms], mode, key_size, key_data, iv_size, iv_data, data, size);
    }  // foreach algorithm
}

void test_crypt_algorithms(uint32 cooltime, uint32 unitsize) {
    console_color concolor;

    ossl_set_cooltime(cooltime);
    ossl_set_unitsize(unitsize);

    basic_stream bs;
    bs << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::white) << "cooltime " << ossl_get_cooltime() << " unitsize "
       << ossl_get_unitsize() << concolor.turnoff();
    _logger->writeln(bs);

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
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::cbc, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                            strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::cfb %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::cfb, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                            strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::cfb1 %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb1, 16, keydata, 16, iv,
                            (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::cfb8 %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(cfbx_algorithm_table), cfbx_algorithm_table, crypt_mode_t::cfb8, 16, keydata, 16, iv,
                            (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ofb %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::ofb, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                            strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ecb %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(algorithm_table), algorithm_table, crypt_mode_t::ecb, 16, keydata, 16, iv, (byte_t*)constexpr_text,
                            strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ctr %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(ctr_algorithm_table), ctr_algorithm_table, crypt_mode_t::ctr, 16, keydata, 16, iv,
                            (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::gcm %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(gcm_algorithm_table), gcm_algorithm_table, crypt_mode_t::gcm, 16, keydata, 16, iv,
                            (byte_t*)constexpr_text, strlen(constexpr_text));
        _test_case.begin("openssl_crypt crypt_mode_t::ccm %s", condition.c_str());
        do_test_crypto_loop(&openssl_crypt, RTL_NUMBER_OF(gcm_algorithm_table), gcm_algorithm_table, crypt_mode_t::ccm, 16, keydata, 16, iv,
                            (byte_t*)constexpr_text, strlen(constexpr_text));
    }
    __finally2 {
        // do nothing
    }
}
