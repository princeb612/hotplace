/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 *  RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 *  RFC 8017 PKCS #1: RSA Cryptography Specifications Version 2.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_crypt::encrypt(const EVP_PKEY *pkey, const binary_t &plaintext, binary_t &ciphertext, crypt_enc_t mode) {
    return encrypt(pkey, &plaintext[0], plaintext.size(), ciphertext, mode);
}

return_t openssl_crypt::encrypt(const EVP_PKEY *pkey, const byte_t *stream, size_t size, binary_t &ciphertext, crypt_enc_t mode) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX *pkey_context = nullptr;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        int ret_openssl = 1;

        ciphertext.resize(0);

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_context = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, nullptr);

        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_encrypt_init(pkey_context);

        int id = EVP_PKEY_id(pkey);
        if (EVP_PKEY_RSA == id) {
            switch (mode) {
                case crypt_enc_t::rsa_1_5:
                    // padding
                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PADDING);
                    break;
                case crypt_enc_t::rsa_oaep:
                case crypt_enc_t::rsa_oaep256:
                case crypt_enc_t::rsa_oaep384:
                case crypt_enc_t::rsa_oaep512: {
                    // OAEP
                    hash_algorithm_t alg = hash_algorithm_t::sha1;
                    const EVP_MD *md = nullptr;

                    switch (mode) {
                        case crypt_enc_t::rsa_oaep:
                            alg = hash_algorithm_t::sha1;
                            break;
                        case crypt_enc_t::rsa_oaep256:
                            alg = hash_algorithm_t::sha2_256;
                            break;
                        case crypt_enc_t::rsa_oaep384:
                            alg = hash_algorithm_t::sha2_384;
                            break;
                        case crypt_enc_t::rsa_oaep512:
                            alg = hash_algorithm_t::sha2_512;
                            break;
                        default:
                            break;
                    }
                    md = advisor->find_evp_md(alg);

                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_OAEP_PADDING);
                    EVP_PKEY_CTX_set_rsa_oaep_md(pkey_context, md);
                    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context, md);
                } break;
                case crypt_enc_undefined:
                    break;
                case ecies:
                default: {
                    ret = errorcode_t::not_supported;
                } break;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t bufsize = 0;
        ret_openssl = EVP_PKEY_encrypt(pkey_context, nullptr, &bufsize, stream, size);
        if (ret_openssl < 1) {
            // if (-2 == ret_openssl) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ciphertext.resize(bufsize);
        ret_openssl = EVP_PKEY_encrypt(pkey_context, &ciphertext[0], &bufsize, stream, size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
    }
    __finally2 {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free(pkey_context);
        }
    }
    return ret;
}

return_t openssl_crypt::decrypt(const EVP_PKEY *pkey, const binary_t &ciphertext, binary_t &plaintext, crypt_enc_t mode) {
    return decrypt(pkey, &ciphertext[0], ciphertext.size(), plaintext, mode);
}

return_t openssl_crypt::decrypt(const EVP_PKEY *pkey, const byte_t *stream, size_t size, binary_t &plaintext, crypt_enc_t mode) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX *pkey_context = nullptr;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        int ret_openssl = 1;

        plaintext.resize(0);

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bool is_private = false;
        ret = is_private_key(pkey, is_private);
        if (false == is_private) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_context = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, nullptr);

        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_decrypt_init(pkey_context);

        if (EVP_PKEY_RSA == EVP_PKEY_id(pkey)) {
            switch (mode) {
                case crypt_enc_t::rsa_1_5:
                    // padding
                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PADDING);
                    break;
                case crypt_enc_t::rsa_oaep:
                case crypt_enc_t::rsa_oaep256:
                case crypt_enc_t::rsa_oaep384:
                case crypt_enc_t::rsa_oaep512: {
                    // OAEP
                    hash_algorithm_t alg = hash_algorithm_t::sha1;
                    const EVP_MD *md = nullptr;

                    switch (mode) {
                        case crypt_enc_t::rsa_oaep:
                            alg = hash_algorithm_t::sha1;
                            break;
                        case crypt_enc_t::rsa_oaep256:
                            alg = hash_algorithm_t::sha2_256;
                            break;
                        case crypt_enc_t::rsa_oaep384:
                            alg = hash_algorithm_t::sha2_384;
                            break;
                        case crypt_enc_t::rsa_oaep512:
                            alg = hash_algorithm_t::sha2_512;
                            break;
                        default:
                            break;
                    }
                    md = advisor->find_evp_md(alg);

                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_OAEP_PADDING);
                    EVP_PKEY_CTX_set_rsa_oaep_md(pkey_context, md);
                    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context, md);
                } break;
                default:
                    break;
            }
        }

        size_t bufsize = 0;
        ret_openssl = EVP_PKEY_decrypt(pkey_context, nullptr, &bufsize, stream, size);
        if (ret_openssl < 1) {
            // if (-2 == ret_openssl) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        plaintext.resize(bufsize);
        ret_openssl = EVP_PKEY_decrypt(pkey_context, &plaintext[0], &bufsize, stream, size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        plaintext.resize(bufsize);
    }
    __finally2 {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free(pkey_context);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
