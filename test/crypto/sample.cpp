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
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {}
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
    const binary_t& input = str2bin(vector->msg);
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
        if ((tag != tag1) || (encrypted != expect)) {
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
    openssl_crypt aead;

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

void test_cipher_encrypt() {
    _test_case.begin("cipher_encrypt");
    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto lambda_test = [&](crypt_algorithm_t alg, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size) -> void {
        return_t ret = errorcode_t::success;
        cipher_encrypt_builder builder;
        auto cipher = builder.set(alg, mode).build();
        if (cipher) {
            binary_t ciphertext;
            ret = cipher->encrypt(key, iv, stream, size, ciphertext);
            _logger->hdump("> encrypt", ciphertext, 16, 3);
            _test_case.test(ret, __FUNCTION__, "encrypt alg %s", advisor->nameof_cipher(alg, mode));
            if (errorcode_t::success == ret) {
                binary_t plaintext;
                ret = cipher->decrypt(key, iv, ciphertext, plaintext);
                _logger->hdump("> decrypt", plaintext, 16, 3);
                _test_case.test(ret, __FUNCTION__, "decrypt alg %s", advisor->nameof_cipher(alg, mode));
            }
            cipher->release();
        }
    };

    binary_t key = base16_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    binary_t iv = base16_decode("000102030405060708090a0b0c0d0e0f");
    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t len = strlen(sample);
    lambda_test(aes128, cbc, key, iv, (byte_t*)sample, len);
    lambda_test(aes128, cfb, key, iv, (byte_t*)sample, len);
    lambda_test(aes128, ofb, key, iv, (byte_t*)sample, len);
    lambda_test(aes192, cbc, key, iv, (byte_t*)sample, len);
    lambda_test(aes192, cfb, key, iv, (byte_t*)sample, len);
    lambda_test(aes192, ofb, key, iv, (byte_t*)sample, len);
    lambda_test(aes256, cbc, key, iv, (byte_t*)sample, len);
    lambda_test(aes256, cfb, key, iv, (byte_t*)sample, len);
    lambda_test(aes256, ofb, key, iv, (byte_t*)sample, len);
    lambda_test(chacha20, crypt_cipher, key, iv, (byte_t*)sample, len);
}

void test_crypto_encrypt() {
    _test_case.begin("crypto_encrypt");

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    crypto_key key;
    crypto_keychain keychain;

    {
        const char* n =
            "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-"
            "QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_"
            "3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";
        const char* e = "AQAB";
        const char* d =
            "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_"
            "qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-"
            "LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ";
        keychain.add_rsa_b64u(&key, nid_rsa, n, e, d, keydesc("RSA", "RSA"));
    }

    auto lambda_test = [&](crypt_enc_t enc, const byte_t* stream, size_t size) -> void {
        return_t ret = errorcode_t::success;
        const EVP_PKEY* pkey = key.find("RSA");
        crypto_encrypt_builder builder;
        auto crypto = builder.set(enc).build();
        if (crypto) {
            binary_t ciphertext;
            ret = crypto->encrypt(pkey, stream, size, ciphertext);
            _logger->hdump("> ciphertext", ciphertext, 16, 3);
            _test_case.test(ret, __FUNCTION__, "encrypt enc %i", enc);
            if (errorcode_t::success == ret) {
                binary_t plaintext;
                ret = crypto->decrypt(pkey, ciphertext, plaintext);
                _logger->hdump("> ciphertext", plaintext, 16, 3);
                _test_case.test(ret, __FUNCTION__, "decrypt enc %i", enc);
            }
            crypto->release();
        }
    };

    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t len = strlen(sample);
    lambda_test(rsa_1_5, (byte_t*)sample, len);
    lambda_test(rsa_oaep, (byte_t*)sample, len);
    lambda_test(rsa_oaep256, (byte_t*)sample, len);
    lambda_test(rsa_oaep384, (byte_t*)sample, len);
    lambda_test(rsa_oaep512, (byte_t*)sample, len);
}

void test_crypto_aead() {
    _test_case.begin("crypto_aead");

    binary_t key = base16_decode_rfc("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    binary_t iv = base16_decode_rfc("000102030405060708090a0b0c0d0e0f");
    binary_t aad = base16_decode_rfc("000102030405060708090a0b0c0d0e0f");
    binary_t nonce;
    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t size = strlen(sample);

    auto lambda = [&](const char* text, crypto_aead_scheme_t scheme, const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size,
                      const binary_t& aad) -> void {
        return_t ret = errorcode_t::success;
        crypto_aead_builder builder;
        auto aead = builder.set_scheme(scheme).build();
        binary_t ciphertext;
        binary_t plaintext;
        binary_t tag;
        if (aead) {
            ret = aead->encrypt(key, iv, stream, size, ciphertext, aad, tag);
            _logger->hdump("> ciphertext", ciphertext, 16, 3);
            _logger->hdump("> tag", tag, 16, 3);
            _test_case.test(ret, __FUNCTION__, "%s #encrypt", text);

            ret = aead->decrypt(key, iv, ciphertext, plaintext, aad, tag);
            _logger->hdump("> plaintext", plaintext, 16, 3);
            _test_case.test(ret, __FUNCTION__, "%s #decrypt", text);

            aead->release();
        }
    };

    lambda("aes128gcm", aead_scheme_aes128_gcm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes192gcm", aead_scheme_aes192_gcm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes256gcm", aead_scheme_aes256_gcm, key, iv, (byte_t*)sample, size, aad);

    lambda("aes128ccm", aead_scheme_aes128_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes192ccm", aead_scheme_aes192_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes256ccm", aead_scheme_aes256_ccm, key, iv, (byte_t*)sample, size, aad);

    lambda("aes128ccm8", aead_scheme_aes128_ccm8, key, iv, (byte_t*)sample, size, aad);
    lambda("aes192ccm8", aead_scheme_aes192_ccm8, key, iv, (byte_t*)sample, size, aad);
    lambda("aes256ccm8", aead_scheme_aes256_ccm8, key, iv, (byte_t*)sample, size, aad);

    openssl_chacha20_iv(nonce, 1, iv);
    lambda("chacha20-poly1305", aead_scheme_chacha20_poly1305, key, nonce, (byte_t*)sample, size, aad);

    // RFC 7539 testvector
    for (auto i = 0; i < sizeof_test_vector_rfc7539; i++) {
        auto item = test_vector_rfc7539 + i;
        if (0 == strcmp("chacha20-poly1305", item->alg)) {
            return_t ret = errorcode_t::success;
            binary_t key = base16_decode_rfc(item->key);
            binary_t iv = base16_decode_rfc(item->iv);
            binary_t aad = base16_decode_rfc(item->aad);
            binary_t tag = base16_decode_rfc(item->tag);
            binary_t expect = base16_decode_rfc(item->expect);
            binary_t nonce;
            binary_t ciphertext;
            binary_t plaintext;
            auto counter = item->counter;
            auto msg = item->msg;

            openssl_chacha20_iv(nonce, counter, iv);
            crypto_aead_builder builder;
            auto aead = builder.set_scheme(aead_scheme_chacha20_poly1305).build();
            if (aead) {
                binary_t t;

                ret = aead->encrypt(key, nonce, (byte_t*)msg, strlen(msg), ciphertext, aad, t);
                _logger->hdump("> ciphertext", ciphertext, 16, 3);
                _test_case.assert(tag == t, __FUNCTION__, "#tag");
                _test_case.assert(expect == ciphertext, __FUNCTION__, "#expect");
                _test_case.test(ret, __FUNCTION__, "#encrypt");

                ret = aead->decrypt(key, nonce, ciphertext, plaintext, aad, t);
                _logger->hdump("> plaintext", plaintext, 16, 3);
                _test_case.test(ret, __FUNCTION__, "#decrypt");

                aead->release();
            }
        }
    }
}

void test_crypto_key() {
    _test_case.begin("crypto_key");
    return_t ret = errorcode_t::success;
    crypto_key key;
    crypto_keychain keychain;
    basic_stream bs;

    // public, private
    keychain.add_ec_b64u(&key, "P-256", "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                         "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM", keydesc("11"));
    keychain.add_ec_b64u(&key, "P-384", "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
                         "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s", "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo",
                         keydesc("P384"));
    keychain.add_ec_b64u(&key, "P-521", "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                         "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                         "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
                         keydesc("bilbo.baggins@hobbiton.example", "ES512"));
    keychain.add_ec_b16(&key, "Ed25519", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", keydesc("11", "EdDSA"));
    keychain.add_ec_b16(&key, "Ed448", "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180", "",
                        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
                        keydesc("ed448", "EdDSA"));
    keychain.add_ec_b16(&key, "P-256", "863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c",
                        "ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca", "d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5",
                        keydesc("Alice Lovelace", "ES256"));
    keychain.add_ec_b16(&key, "X25519", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E", "",
                        "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655", keydesc("X25519-1", "X25519"));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", keydesc("our-secret", nullptr, crypto_use_t::use_enc));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", nullptr, crypto_use_t::use_enc));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA",
                          keydesc("sec-64", nullptr, crypto_use_t::use_enc));
    keychain.add_rsa_b16(
        &key, nid_rsa,
        "bc7e29d0df7e20cc9dc8d509e0f68895922af0ef452190d402c61b554334a7bf91c9a570240f994fae1b69035bcfad4f7e249eb26087c2665e7c958c967b1517413dc3f97a"
        "431691a5999b257cc6cd356bad168d929b8bae9020750e74cf60f6fd35d6bb3fc93fc28900478694f508b33e7c00e24f90edf37457fc3e8efcfd2f42306301a8205ab74051"
        "5331d5c18f0c64d4a43be52fc440400f6bfc558a6e32884c2af56f29e5c52780cea7285f5c057fc0dfda232d0ada681b01495d9d0e32196633588e289e59035ff664f05618"
        "9f2f10fe05827b796c326e3e748ffa7c589ed273c9c43436cddb4a6a22523ef8bcb2221615b799966f1aba5bc84b7a27cf",
        "010001",
        "0969ff04fcc1e1647c20402cf3f736d4cae33f264c1c6ee3252cfcc77cdef533d700570ac09a50d7646edfb1f86a13bcabcf00bd659f27813d08843597271838bc46ed4743"
        "fe741d9bc38e0bf36d406981c7b81fce54861cebfb85ad23a8b4833c1bee18c05e4e436a869636980646eecb839e4daf434c9c6dfbf3a55ce1db73e4902f89384bd6f9ecd3"
        "399fb1ed4b83f28d356c8e619f1f0dc96bbe8b75c1812ca58f360259eaeb1d17130c3c0a2715a99be49898e871f6088a29570dc2ffa0cefffa27f1f055cbaabfd8894e0cc2"
        "4f176e34ebad32278a466f8a34a685acc8207d9ec1fcbbd094996dc73c6305fca31668be57b1699d0bb456cc8871bffbcd",
        keydesc("meriadoc.brandybuck@rsa.example"));

    // generate
    keychain.add_dh(&key, NID_ffdhe2048, "ffdhe2048");
    keychain.add_dh(&key, NID_ffdhe3072, "ffdhe3072");
    keychain.add_dh(&key, NID_ffdhe4096, "ffdhe4096");
    keychain.add_dh(&key, NID_ffdhe6144, "ffdhe6144");
    keychain.add_dh(&key, NID_ffdhe8192, "ffdhe8192");

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        bs.printf(R"(> kid "%s")", item->get_desc().get_kid_cstr());
        bs.printf("\n");
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->writeln(bs);
        bs.clear();
    };
    key.for_each(dump_crypto_key, nullptr);

    json_web_key jwk;
    ret = jwk.write(&key, &bs);
    _logger->writeln(bs);
    bs.clear();
    _test_case.test(ret, __FUNCTION__, "test #1");

    cbor_web_key cwk;
    ret = cwk.diagnose(&key, &bs);
    _logger->writeln(bs);
    bs.clear();
    _test_case.test(ret, __FUNCTION__, "test #2");
}

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt);
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
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

        test_cipher_encrypt();
        test_crypto_encrypt();
        test_crypto_aead();

        test_crypto_key();
    }
    __finally2 { openssl_cleanup(); }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    _logger->consoleln("openssl 3 deprected bf, idea, seed");
    return _test_case.result();
}
