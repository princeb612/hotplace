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
            _logger->hdump("> key", key, 16, 3);
            _logger->hdump("> iv", iv, 16, 3);
            _logger->hdump("> aad", aad, 16, 3);
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

void test_aead_cbc() {
    openssl_crypt crypt;

    // https://tls12.xargs.org/#client-handshake-finished
    // # TLS Record
    //    00000000 : 16 03 03 00 40 40 41 42 43 44 45 46 47 48 49 4A | ....@@ABCDEFGHIJ
    //    00000010 : 4B 4C 4D 4E 4F 22 7B C9 BA 81 EF 30 F2 A8 A7 8F | KLMNO"{....0....
    //    00000020 : F1 DF 50 84 4D 58 04 B7 EE B2 E2 14 C3 2B 68 92 | ..P.MX.......+h.
    //    00000030 : AC A3 DB 7B 78 07 7F DD 90 06 7C 51 6B AC B3 BA | ...{x.....|Qk...
    //    00000040 : 90 DE DF 72 0F -- -- -- -- -- -- -- -- -- -- -- | ...r.

    // const char* record_header = "16 03 03 00 40";
    // size_t record_size = 5;
    // const char* encryption_iv = "40 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f";
    // size_t ivsize = 16;
    const char* encdata =
        "22 7b c9 ba 81 ef 30 f2 a8 a7 8f f1 df 50 84 4d"
        "58 04 b7 ee b2 e2 14 c3 2b 68 92 ac a3 db 7b 78"
        "07 7f dd 90 06 7c 51 6b ac b3 ba 90 de df 72 0f";
    const char* content_aad = "00 00 00 00 00 00 00 00 16 03 03";  // 00 10
    const char* content = "14 00 00 0c cf 91 96 26 f1 36 0c 53 6a aa d7 3a -- -- --";

    const binary_t& ciphertext = base16_decode_rfc(encdata);
    const binary_t& key = base16_decode("f656d037b173ef3e11169f27231a84b6");
    const binary_t& iv = base16_decode("404142434445464748494a4b4c4d4e4f");
    const binary_t& mackey = base16_decode("1b7d117c7d5f690bc263cae8ef60af0f1878acc2");
    const binary_t& aad = base16_decode_rfc(content_aad);
    const binary_t& plaintext = base16_decode_rfc(content);

    {
        _logger->hdump("> key", key, 16, 3);
        _logger->hdump("> iv", iv, 16, 3);
        _logger->hdump("> mackey", mackey, 16, 3);
        _logger->hdump("> aad", aad, 16, 3);
    }
    {
        binary_t out;
        size_t ptsize = 0;
        crypt.cbc_hmac_tls_decrypt(aes128, sha1, key, mackey, iv, aad, ciphertext, out, ptsize);
        _logger->hdump("> ciphertext", ciphertext, 16, 3);
        _logger->hdump("> plaintag", out, 16, 3);
        binary_t pt(out.begin(), out.begin() + ptsize);
        _logger->writeln("> plaintext.size %zi", ptsize);
        _logger->hdump("> plaintext", pt, 16, 3);
        _test_case.assert(plaintext == pt, __FUNCTION__, "AES-128-CBC-SHA #decryption");
    }
    {
        binary_t out;
        crypt.cbc_hmac_tls_encrypt(aes128, sha1, key, mackey, iv, aad, plaintext, out);
        _logger->hdump("> plaintext", plaintext, 16, 3);
        _logger->hdump("> ciphertext", out, 16, 3);
        _test_case.assert(ciphertext == out, __FUNCTION__, "AES-128-CBC-SHA #encryption");
    }
}
