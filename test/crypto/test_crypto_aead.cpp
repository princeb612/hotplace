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

    binary_t key = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"));
    binary_t iv = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f"));
    binary_t aad = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f"));
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

    lambda("aes128-gcm", aead_scheme_aes128_gcm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes192-gcm", aead_scheme_aes192_gcm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes256-gcm", aead_scheme_aes256_gcm, key, iv, (byte_t*)sample, size, aad);

    lambda("aes128-ccm", aead_scheme_aes128_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes192-ccm", aead_scheme_aes192_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("aes256-ccm", aead_scheme_aes256_ccm, key, iv, (byte_t*)sample, size, aad);

    lambda("aes128-ccm8", aead_scheme_aes128_ccm8, key, iv, (byte_t*)sample, size, aad);
    lambda("aes192-ccm8", aead_scheme_aes192_ccm8, key, iv, (byte_t*)sample, size, aad);
    lambda("aes256-ccm8", aead_scheme_aes256_ccm8, key, iv, (byte_t*)sample, size, aad);

    openssl_chacha20_iv(nonce, 1, iv);
    lambda("chacha20-poly1305", aead_scheme_chacha20_poly1305, key, nonce, (byte_t*)sample, size, aad);

    lambda("aes128-gcm", aead_scheme_aes128_gcm, key, iv, nullptr, 0, aad);
    lambda("aes192-gcm", aead_scheme_aes192_gcm, key, iv, nullptr, 0, aad);
    lambda("aes256-gcm", aead_scheme_aes256_gcm, key, iv, nullptr, 0, aad);

    lambda("aes128-ccm", aead_scheme_aes128_ccm, key, iv, nullptr, 0, aad);
    lambda("aes192-ccm", aead_scheme_aes192_ccm, key, iv, nullptr, 0, aad);
    lambda("aes256-ccm", aead_scheme_aes256_ccm, key, iv, nullptr, 0, aad);

    lambda("aes128-ccm8", aead_scheme_aes128_ccm8, key, iv, nullptr, 0, aad);
    lambda("aes192-ccm8", aead_scheme_aes192_ccm8, key, iv, nullptr, 0, aad);
    lambda("aes256-ccm8", aead_scheme_aes256_ccm8, key, iv, nullptr, 0, aad);

    lambda("chacha20-poly1305", aead_scheme_chacha20_poly1305, key, nonce, nullptr, 0, aad);
}
