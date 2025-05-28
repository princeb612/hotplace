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
    _test_case.begin("test CCM EVP_CTRL_CCM_SET_L, EVP_CTRL_AEAD_SET_TAG");
    binary_t key = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"));
    binary_t iv = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f"));
    binary_t aad = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f"));
    binary_t nonce;
    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t size = strlen(sample);

    auto lambda = [&](const char* text, crypt_algorithm_t alg, crypt_mode_t mode, int lsize, int tsize, const binary_t& key, const binary_t& iv,
                      const byte_t* stream, size_t size, const binary_t& aad) -> void {
        return_t ret = errorcode_t::success;
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        crypt_context_t* handle_ccm = nullptr;
        binary_t ciphertext;
        binary_t plaintext;
        binary_t plaintext_ccm;
        binary_t tag;

        crypt.open(&handle, alg, mode, &key[0], key.size(), &iv[0], iv.size());

        crypt.open(&handle_ccm, alg, ccm, &key[0], key.size(), &iv[0], iv.size());
        crypt.set(handle_ccm, crypt_ctrl_lsize, lsize);  // CCM_SET_L
        crypt.set(handle_ccm, crypt_ctrl_tsize, tsize);  // CCM_SET_IVLEN=15-L

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
        ret = crypt.decrypt(handle_ccm, ciphertext, plaintext_ccm, aad, tag);
        {
            _logger->hdump("> plaintext", plaintext_ccm, 16, 3);
            _test_case.test(ret, __FUNCTION__, "%s #decrypt", text);
        }
        _test_case.assert(plaintext == plaintext_ccm, __FUNCTION__, "%s #compare", text);

        crypt.close(handle);
        crypt.close(handle_ccm);
    };

    // compare ccm16 and CCM_SET_L 3, CCM_SET_IVLEN=15-L=12, AEAD_SET_TAG 16
    lambda("AEAD_AES_128_CCM", aes128, ccm16, 3, 16, key, iv, (byte_t*)sample, size, aad);
    lambda("AEAD_AES_192_CCM", aes192, ccm16, 3, 16, key, iv, (byte_t*)sample, size, aad);
    lambda("AEAD_AES_256_CCM", aes256, ccm16, 3, 16, key, iv, (byte_t*)sample, size, aad);

    // compare ccm8 and CCM_SET_L 3, CCM_SET_IVLEN=15-L=12, AEAD_SET_TAG 8
    lambda("AEAD_AES_128_CCM", aes128, ccm8, 3, 8, key, iv, (byte_t*)sample, size, aad);
    lambda("AEAD_AES_192_CCM", aes192, ccm8, 3, 8, key, iv, (byte_t*)sample, size, aad);
    lambda("AEAD_AES_256_CCM", aes256, ccm8, 3, 8, key, iv, (byte_t*)sample, size, aad);
}
