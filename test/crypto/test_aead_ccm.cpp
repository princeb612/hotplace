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

void test_aead_ccm() {
    _test_case.begin("AEAD_AES_128_CCM, AEAD_AES_192_CCM, AEAD_AES_256_CCM");
    binary_t key = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"));
    binary_t iv = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f"));
    binary_t aad = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f"));
    binary_t nonce;
    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t size = strlen(sample);
    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto lambda = [&](const char* text, crypto_scheme_t scheme, const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size,
                      const binary_t& aad) -> void {
        return_t ret = errorcode_t::success;
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        binary_t ciphertext;
        binary_t plaintext;
        binary_t plaintext_ccm;
        binary_t tag;

        auto hint = advisor->hintof_cipher(scheme);

        crypt.open(&handle, typeof_alg(hint), typeof_mode(hint), &key[0], key.size(), &iv[0], iv.size());

        crypt.set(handle, crypt_ctrl_nsize, hint->nsize);  // IV
        crypt.set(handle, crypt_ctrl_tsize, hint->tsize);  // TAG

        ret = crypt.encrypt(handle, stream, size, ciphertext, aad, tag);

        {
            _logger->hdump("> key", key, 16, 3);
            _logger->hdump("> iv", iv, 16, 3);
            _logger->hdump("> aad", aad, 16, 3);
            _logger->hdump("> ciphertext", ciphertext, 16, 3);
            _logger->hdump("> tag", tag, 16, 3);
            _test_case.test(ret, __FUNCTION__, "%s #encrypt", text);
        }

        ret = crypt.decrypt(handle, &ciphertext[0], ciphertext.size(), plaintext, aad, tag);
        {
            _logger->hdump("> plaintext", plaintext, 16, 3);
            _test_case.test(ret, __FUNCTION__, "%s #decrypt", text);
        }

        crypt.close(handle);
    };

    // SET_L=8, SET_IVLEN=15-L=4, AEAD_SET_TAG=14
    lambda("AES_128_GCM", crypto_scheme_aes_128_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("AES_192_GCM", crypto_scheme_aes_192_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("AES_256_GCM", crypto_scheme_aes_256_ccm, key, iv, (byte_t*)sample, size, aad);

    // SET_L=8, SET_IVLEN=15-L=4, AEAD_SET_TAG=14
    lambda("AES_128_CCM", crypto_scheme_aes_128_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("AES_192_CCM", crypto_scheme_aes_192_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("AES_256_CCM", crypto_scheme_aes_256_ccm, key, iv, (byte_t*)sample, size, aad);

    // SET_L=3, SET_IVLEN=15-L=12, AEAD_SET_TAG=16
    lambda("AEAD_AES_128_CCM", crypto_scheme_tls_aes_128_ccm, key, iv, (byte_t*)sample, size, aad);
    lambda("AEAD_AES_256_CCM", crypto_scheme_tls_aes_256_ccm, key, iv, (byte_t*)sample, size, aad);

    // SET_L=3, SET_IVLEN=15-L=12, AEAD_SET_TAG=8
    lambda("AEAD_AES_128_CCM", crypto_scheme_tls_aes_128_ccm_8, key, iv, (byte_t*)sample, size, aad);
    lambda("AEAD_AES_192_CCM", crypto_scheme_tls_aes_256_ccm_8, key, iv, (byte_t*)sample, size, aad);
}
