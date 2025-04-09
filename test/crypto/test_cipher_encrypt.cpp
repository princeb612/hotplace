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

    binary_t key = std::move(base16_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    binary_t iv = std::move(base16_decode("000102030405060708090a0b0c0d0e0f"));
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
    lambda_test(chacha20, mode_cipher, key, iv, (byte_t*)sample, len);
}
