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

void do_test_chacha20_rfc7539_testvector(const test_vector_rfc7539_t* vector) {
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
        do_test_chacha20_rfc7539_testvector(test_vector_rfc7539 + i);
    }
}

void test_chacha20_rfc7539_crypto_aead() {
    _test_case.begin("RFC 7539/8439");
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
