/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_crypt_evp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 *  RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 *  RFC 8017 PKCS #1: RSA Cryptography Specifications Version 2.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_crypt::encrypt(const EVP_PKEY* pkey, const binary_t& plaintext, binary_t& ciphertext, crypt_enc_t mode) {
    return encrypt(pkey, plaintext.data(), plaintext.size(), ciphertext, mode);
}

return_t openssl_crypt::encrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& ciphertext, crypt_enc_t mode) {
    ciphertext.resize(0);

    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_PKEY_CTX_ptr pkey_context;
    size_t bufsize = 0;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey) && (nullptr != stream); })
        .run_pipe([&]() -> int {
            pkey_context = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new((EVP_PKEY*)pkey, nullptr)));
            return pkey_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> return_t {
            crypto_kty_t kty = kty_unknown;
            uint32 nid = 0;
            advisor->ktyof_evp_pkey(pkey, kty, nid);
            if (kty_rsa == kty) {
                switch (mode) {
                    case crypt_enc_t::rsa_1_5:
                    case crypt_enc_t::rsa_oaep:
                    case crypt_enc_t::rsa_oaep256:
                    case crypt_enc_t::rsa_oaep384:
                    case crypt_enc_t::rsa_oaep512:
                        return errorcode_t::success;
                    default:
                        return errorcode_t::not_supported;
                }
            } else {
                // kty_rsapss signing only
                return errorcode_t::bad_request;
            }
        })
        .run_pipe([&]() -> int { return EVP_PKEY_encrypt_init(pkey_context.get()); })
        .run_pipe([&]() -> int {
            int id = EVP_PKEY_id(pkey);
            if (EVP_PKEY_RSA == id) {
                switch (mode) {
                    case crypt_enc_t::rsa_1_5:
                        // padding
                        EVP_PKEY_CTX_set_rsa_padding(pkey_context.get(), RSA_PKCS1_PADDING);
                        break;
                    case crypt_enc_t::rsa_oaep:
                    case crypt_enc_t::rsa_oaep256:
                    case crypt_enc_t::rsa_oaep384:
                    case crypt_enc_t::rsa_oaep512: {
                        // OAEP
                        hash_algorithm_t alg = hash_algorithm_t::sha1;
                        const EVP_MD* md = nullptr;

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

                        EVP_PKEY_CTX_set_rsa_padding(pkey_context.get(), RSA_PKCS1_OAEP_PADDING);
                        EVP_PKEY_CTX_set_rsa_oaep_md(pkey_context.get(), md);
                        EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context.get(), md);
                    } break;
                    default: {
                    } break;
                }
            }
            return 1;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_encrypt(pkey_context.get(), nullptr, &bufsize, stream, size); })
        .run_pipe([&]() -> int {
            ciphertext.resize(bufsize);
            auto rc = EVP_PKEY_encrypt(pkey_context.get(), ciphertext.data(), &bufsize, stream, size);
            ciphertext.resize(bufsize);
            return rc;
        });
    return pipeline.result_to_return_t();
}

return_t openssl_crypt::decrypt(const EVP_PKEY* pkey, const binary_t& ciphertext, binary_t& plaintext, crypt_enc_t mode) {
    return decrypt(pkey, ciphertext.data(), ciphertext.size(), plaintext, mode);
}

return_t openssl_crypt::decrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& plaintext, crypt_enc_t mode) {
    plaintext.resize(0);

    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_PKEY_CTX_ptr pkey_context;
    size_t bufsize = 0;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != stream); })
        .run_pipe([&]() -> int {
            bool is_private = false;
            auto rc = is_private_key(pkey, is_private);
            return (errorcode_t::success == rc || is_private) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            pkey_context = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new((EVP_PKEY*)pkey, nullptr)));
            return pkey_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_decrypt_init(pkey_context.get()); })
        .run_pipe([&]() -> int {
            if (EVP_PKEY_RSA == EVP_PKEY_id(pkey)) {
                switch (mode) {
                    case crypt_enc_t::rsa_1_5:
                        // padding
                        return EVP_PKEY_CTX_set_rsa_padding(pkey_context.get(), RSA_PKCS1_PADDING);
                    case crypt_enc_t::rsa_oaep:
                    case crypt_enc_t::rsa_oaep256:
                    case crypt_enc_t::rsa_oaep384:
                    case crypt_enc_t::rsa_oaep512: {
                        // OAEP
                        hash_algorithm_t alg = hash_algorithm_t::sha1;
                        const EVP_MD* md = nullptr;

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

                        EVP_PKEY_CTX_set_rsa_padding(pkey_context.get(), RSA_PKCS1_OAEP_PADDING);
                        EVP_PKEY_CTX_set_rsa_oaep_md(pkey_context.get(), md);
                        return EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context.get(), md);
                    } break;
                    default: {
                        // do nothing
                    } break;
                        return 0;
                }
            }
            return 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_decrypt(pkey_context.get(), nullptr, &bufsize, stream, size); })
        .run_pipe([&]() -> int {
            plaintext.resize(bufsize);
            auto rc = EVP_PKEY_decrypt(pkey_context.get(), plaintext.data(), &bufsize, stream, size);
            plaintext.resize(bufsize);
            return rc;
        });
    return pipeline.result_to_return_t();
}

}  // namespace crypto
}  // namespace hotplace
