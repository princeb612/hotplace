/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_aead.hpp>

namespace hotplace {
namespace crypto {

crypto_aead_aes::crypto_aead_aes(crypto_aead_scheme_t scheme) : crypto_aead(scheme) {}

return_t crypto_aead_aes::encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad,
                                  binary_t& tag) {
    return encrypt(key, iv, &plaintext[0], plaintext.size(), ciphertext, aad, tag);
}

std::string crypto_aead_aes::algorithm_str() {
    std::string alg;
    switch (get_scheme()) {
        case aead_scheme_aes128_gcm:
            alg = "aes-128-gcm";
            break;
        case aead_scheme_aes128_ccm:
        case aead_scheme_aes128_ccm8:
            alg = "aes-128-ccm";
            break;
        case aead_scheme_aes192_gcm:
            alg = "aes-192-gcm";
            break;
        case aead_scheme_aes192_ccm:
        case aead_scheme_aes192_ccm8:
            alg = "aes-192-ccm";
            break;
        case aead_scheme_aes256_gcm:
            alg = "aes-256-gcm";
            break;
        case aead_scheme_aes256_ccm:
        case aead_scheme_aes256_ccm8:
            alg = "aes-256-ccm";
            break;
    }
    return alg;
}

return_t crypto_aead_aes::encrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& ciphertext, const binary_t& aad,
                                  binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) && size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_crypt crypt;
        std::string alg = algorithm_str();
        switch (get_scheme()) {
            case aead_scheme_aes128_ccm8:
            case aead_scheme_aes192_ccm8:
            case aead_scheme_aes256_ccm8: {
                encrypt_option_t option_ccm8[] = {{crypt_ctrl_tsize, 8}, {}};
                ret = crypt.encrypt(alg.c_str(), key, iv, stream, size, ciphertext, aad, tag, option_ccm8);
            } break;
            default: {
                ret = crypt.encrypt(alg.c_str(), key, iv, stream, size, ciphertext, aad, tag);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_aead_aes::decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                                  const binary_t& tag) {
    return decrypt(key, iv, &ciphertext[0], ciphertext.size(), plaintext, aad, tag);
}

return_t crypto_aead_aes::decrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& plaintext, const binary_t& aad,
                                  const binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) && size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        openssl_crypt crypt;
        encrypt_option_t* optionptr = nullptr;
        std::string alg = algorithm_str();
        switch (get_scheme()) {
            case aead_scheme_aes128_ccm8:
            case aead_scheme_aes192_ccm8:
            case aead_scheme_aes256_ccm8: {
                encrypt_option_t option_ccm8[] = {{crypt_ctrl_tsize, 8}, {}};
                ret = crypt.decrypt(alg.c_str(), key, iv, stream, size, plaintext, aad, tag, option_ccm8);
            } break;
            default: {
                ret = crypt.decrypt(alg.c_str(), key, iv, stream, size, plaintext, aad, tag);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
