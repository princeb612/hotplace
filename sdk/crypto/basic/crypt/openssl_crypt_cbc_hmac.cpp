/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/openssl_crypt.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_crypt::cbc_hmac_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                         const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext, binary_t& tag, uint8 flag) {
    return_t ret = errorcode_t::success;
    switch (flag) {
        case mac_then_encrypt:
            ret = cbc_hmac_mte_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, plaintext, tag);
            break;
        case encrypt_then_mac:
            ret = cbc_hmac_etm_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, plaintext, tag);
            break;
        default:
            ret = invalid_parameter;
            break;
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                         const binary_t& aad, const byte_t* ciphertext, size_t ciphersize, binary_t& plaintext, binary_t& tag, uint8 flag) {
    return_t ret = errorcode_t::success;
    switch (flag) {
        case mac_then_encrypt:
            ret = cbc_hmac_mte_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, ciphersize, plaintext, tag);
            break;
        case encrypt_then_mac:
            ret = cbc_hmac_etm_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, ciphersize, plaintext, tag);
            break;
        default:
            ret = invalid_parameter;
            break;
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                         const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext, binary_t& tag, uint8 flag) {
    return_t ret = errorcode_t::success;
    switch (flag) {
        case mac_then_encrypt:
            ret = cbc_hmac_mte_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, plaintext, tag);
            break;
        case encrypt_then_mac:
            ret = cbc_hmac_etm_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, plaintext, tag);
            break;
        default:
            ret = invalid_parameter;
            break;
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                         const binary_t& aad, const byte_t* ciphertext, size_t ciphersize, binary_t& plaintext, binary_t& tag, uint8 flag) {
    return_t ret = errorcode_t::success;
    switch (flag) {
        case mac_then_encrypt:
            ret = cbc_hmac_mte_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, ciphersize, plaintext, tag);
            break;
        case encrypt_then_mac:
            ret = cbc_hmac_etm_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, aad, ciphertext, ciphersize, plaintext, tag);
            break;
        default:
            ret = invalid_parameter;
            break;
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
