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
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_features() {
    _test_case.begin("features openssl version %08x", OpenSSL_version_num());
    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto query_cipher = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_cipher);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature cipher "%s" [%08x])", feature, spec);
    };
    auto query_md = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_md);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature md "%s" [%08x])", feature, spec);
    };
    auto query_jwa = [&](const hint_jose_encryption_t* item, void* user) -> void {
        bool test = advisor->query_feature(item->alg_name, advisor_feature_jwa);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature JWA "%s" [%08x])", item->alg_name, advisor_feature_jwa);
    };
    auto query_jwe = [&](const hint_jose_encryption_t* item, void* user) -> void {
        bool test = advisor->query_feature(item->alg_name, advisor_feature_jwe);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature JWE "%s" [%08x])", item->alg_name, advisor_feature_jwe);
    };
    auto query_jws = [&](const hint_signature_t* item, void* user) -> void {
        bool test = advisor->query_feature(item->jws_name, advisor_feature_jws);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature JWS "%s" [%08x])", item->jws_name, advisor_feature_jws);
    };
    auto query_cose = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_cose);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature COSE "%s" [%08x])", feature, spec);
    };
    auto query_curve = [&](const char* feature, uint32 spec, void* user) -> void {
        bool test = advisor->query_feature(feature, advisor_feature_curve);
        return_t ret = test ? errorcode_t::success : errorcode_t::not_supported;
        _test_case.test(ret, __FUNCTION__, R"(check feature Elliptic Curve "%s" [%08x])", feature, spec);
    };

    advisor->cipher_for_each(query_cipher, nullptr);
    advisor->md_for_each(query_md, nullptr);
    advisor->jose_for_each_algorithm(query_jwa, nullptr);
    advisor->jose_for_each_encryption(query_jwe, nullptr);
    advisor->jose_for_each_signature(query_jws, nullptr);
    advisor->cose_for_each(query_cose, nullptr);
    advisor->curve_for_each(query_curve, nullptr);
}

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

void test_crypt_routine(crypt_t* crypt_object, crypt_algorithm_t algorithm, crypt_mode_t mode, unsigned key_size, const byte_t* key_data, unsigned iv_size,
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

void test_keywrap_rfc3394_testvector(const test_vector_rfc3394_t* vector) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    _test_case.reset_time();

    crypt_algorithm_t alg = vector->alg;
    const char* algname = vector->algname;
    const binary_t& kek = base16_decode(vector->kek);
    const binary_t& key = base16_decode(vector->key);
    const binary_t& expect = base16_decode(vector->expect);
    const char* msg = vector->message;

    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    binary_t iv;
    binary_fill(iv, 8, 0xa6);
    binary_t out_kw, out_kuw;

    ret = crypt.open(&handle, alg, crypt_mode_t::wrap, kek, iv);
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, &key[0], key.size(), out_kw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            crypto_advisor* advisor = crypto_advisor::get_instance();
            const char* nameof_alg = advisor->nameof_cipher(alg, crypt_mode_t::wrap);
            _logger->writeln("alg %s", nameof_alg);

            _logger->hdump("kek", kek);
            _logger->hdump("key", key);
            _logger->hdump("keywrap", out_kw);
        }

        crypt.decrypt(handle, &out_kw[0], out_kw.size(), out_kuw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("key", out_kuw);
        }

        crypt.close(handle);
    }
    _test_case.assert(out_kw == expect, __FUNCTION__, msg ? msg : "");

    ret = crypt.open(&handle, algname, kek, iv);
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, &key[0], key.size(), out_kw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            crypto_advisor* advisor = crypto_advisor::get_instance();
            const char* nameof_alg = advisor->nameof_cipher(alg, crypt_mode_t::wrap);
            _logger->writeln("alg %s", nameof_alg);

            _logger->hdump("kek", kek);
            _logger->hdump("key", key);
            _logger->hdump("keywrap", out_kw);
        }

        crypt.decrypt(handle, &out_kw[0], out_kw.size(), out_kuw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("key", out_kuw);
        }

        crypt.close(handle);
    }
    _test_case.assert(out_kw == expect, __FUNCTION__, msg ? msg : "");
}

void test_keywrap_rfc3394() {
    _test_case.begin("keywrap");

    for (int i = 0; i < sizeof_test_vector_rfc3394; i++) {
        test_keywrap_rfc3394_testvector(test_vector_rfc3394 + i);
    }
}

void test_chacha20_rfc7539_testvector(const test_vector_rfc7539_t* vector) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    const char* text = vector->text;
    const char* alg = vector->alg;
    const binary_t& key = base16_decode_rfc(vector->key);
    uint32 counter = vector->counter;
    const binary_t& iv = base16_decode_rfc(vector->iv);
    const binary_t& input = strtobin(vector->msg);
    const binary_t& aad = base16_decode_rfc(vector->aad);
    const binary_t& expect = base16_decode_rfc(vector->expect);
    const binary_t& tag1 = base16_decode_rfc(vector->tag);

    openssl_crypt crypt;
    binary_t encrypted;
    binary_t nonce;
    binary_t tag;
    basic_stream bs;

    openssl_chacha20_iv(nonce, counter, iv);
    ret = crypt.encrypt(alg, key, nonce, input, encrypted, aad, tag);
    if (errorcode_t::success == ret) {
        if (tag1.size() && tag.size()) {
            if (tag != tag) {
                ret = errorcode_t::mismatch;
            }
        }
        if (encrypted != expect) {
            ret = errorcode_t::mismatch;
        }
    }

    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);

        _logger->hdump("key", key, 16, 2);
        _logger->hdump("iv", iv, 16, 2);
        _logger->writeln("nonce w/ counter %i", counter);
        _logger->dump(nonce);
        if (aad.size()) {
            _logger->hdump("aad", aad, 16, 2);
        }
        if (tag.size()) {
            _logger->hdump("tag", tag, 16, 2);
        }
        _logger->hdump("input", input, 16, 2);
        _logger->hdump("encrypted", encrypted, 16, 2);
        if (expect.size()) {
            _logger->hdump("expect", expect, 16, 2);
        }
    }

    _test_case.test(ret, __FUNCTION__, "%s %s", text, alg);
}

void test_chacha20_rfc7539() {
    _test_case.begin("RFC 7539/8439");

    // RFC 7539 2.4.  The ChaCha20 Encryption Algorithm
    // RFC 8439 2.4.  The ChaCha20 Encryption Algorithm
    // RFC 7539 2.8.  AEAD Construction
    // RFC 8439 2.8.  AEAD Construction

    for (size_t i = 0; i < sizeof_test_vector_rfc7539; i++) {
        test_chacha20_rfc7539_testvector(test_vector_rfc7539 + i);
    }
}

// Authenticated Encryption with AES-CBC and HMAC-SHA
// AEAD_AES_128_CBC_HMAC_SHA_256
// AEAD_AES_192_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_512

#define dump(var)                             \
    {                                         \
        _logger->hdump(#var, var);            \
        _logger->writeln(base16_encode(var)); \
    }

// https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
// 2.1.  Encryption
// Appendix A.  CBC Encryption and Decryption
return_t test_aead_aes_cbc_hmac_sha2_testvector1(const test_vector_aead_aes_cbc_hmac_sha2_t* vector) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const OPTION& option = _cmdline->value();

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
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        // 2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
        // 2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
        // 2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
        // 2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32

        if (k.size() < std::max(digestsize, keysize)) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mac_key.insert(mac_key.end(), &k[0], &k[0] + digestsize);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            size_t pos = k.size() - keysize;
            enc_key.insert(enc_key.end(), &k[pos], &k[pos] + keysize);
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
        if (option.verbose) {
            dump(s);
        }

        _test_case.assert(base16_decode(vector->s) == s, __FUNCTION__, "%s S = IV || CBC-ENC(ENC_KEY, P || PS)", vector->text);

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        openssl_mac mac;
        mac.hmac(mac_alg, mac_key, content, t);
        t.resize(digestsize);

        _test_case.assert(base16_decode(vector->t) == t, __FUNCTION__, "%s T = MAC(MAC_KEY, A || S || AL)", vector->text);

        /* C = S || T */
        c.insert(c.end(), s.begin(), s.end());
        c.insert(c.end(), t.begin(), t.end());

        if (option.verbose) {
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

void test_aead_aes_cbc_hmac_sha2_testvector2(const test_vector_aead_aes_cbc_hmac_sha2_t* vector) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    openssl_aead aead;

    binary_t q;
    binary_t t;
    ret = aead.aes_cbc_hmac_sha2_encrypt(vector->enc_alg, vector->mac_alg, base16_decode(vector->k), base16_decode(vector->iv), base16_decode(vector->a),
                                         base16_decode(vector->p), q, t);
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump(q);
    }
    _test_case.assert(base16_decode(vector->q) == q, __FUNCTION__, "encrypt %s", vector->text);
    binary_t p;
    ret = aead.aes_cbc_hmac_sha2_decrypt(vector->enc_alg, vector->mac_alg, base16_decode(vector->k), base16_decode(vector->iv), base16_decode(vector->a), q, p,
                                         t);
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump(p);
    }
    _test_case.assert(base16_decode(vector->p) == p, __FUNCTION__, "decrypt %s", vector->text);
}

void test_aead_aes_cbc_hmac_sha2() {
    _test_case.begin("Authenticated Encryption with AES-CBC and HMAC-SHA");

    for (int i = 0; i < sizeof_test_vector_aead_aes_cbc_hmac_sha2; i++) {
        const test_vector_aead_aes_cbc_hmac_sha2_t* vector = test_vector_aead_aes_cbc_hmac_sha2 + i;
        test_aead_aes_cbc_hmac_sha2_testvector1(vector);
        test_aead_aes_cbc_hmac_sha2_testvector2(vector);
    }
}

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt);
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    __try2 {
        openssl_startup();

        auto lambda = [&](trace_category_t category, uint32 event, stream_t* s) -> void {
            std::string ct;
            std::string ev;
            auto advisor = trace_advisor::get_instance();
            advisor->get_names(category, event, ct, ev);
            _logger->writeln("[%s][%s]%.*s", ct.c_str(), ev.c_str(), (unsigned)s->size(), s->data());
        };
        crypto_advisor::trace(lambda);

        test_features();

        validate_openssl_crypt();  // validate wrapper class openssl_crypt

        test_crypt_algorithms(10, 4096);  // performance (for large stream encryption performance, just check error occurrence)
        test_crypt_algorithms(0, 0);      // speed

        test_keywrap_rfc3394();

        test_chacha20_rfc7539();

        test_aead_aes_cbc_hmac_sha2();
    }
    __finally2 { openssl_cleanup(); }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    _logger->consoleln("openssl 3 deprected bf, idea, seed");
    return _test_case.result();
}
