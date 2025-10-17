/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLPQC__
#define __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLPQC__

#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief ML-KEM
 * @remarks
 *          ML-KEM - openssl-3.5 required
 *              "ML-KEM-512"    1454    EVP_PKEY_ML_KEM_512
 *              "ML-KEM-768"    1455    EVP_PKEY_ML_KEM_768
 *              "ML-KEM-1024"   1456    EVP_PKEY_ML_KEM_1024
 *
 *          oqs-provider - openssl-3.0 required
 */

class openssl_pqc {
   public:
    openssl_pqc();
    ~openssl_pqc();

    return_t encode(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);
    return_t decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);

    return_t encapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& capsulekey, binary_t& sharedsecret);
    return_t decapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, const binary_t& capsulekey, binary_t& sharedsecret);

    return_t sign(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    return_t verify(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
};

}  // namespace crypto
}  // namespace hotplace

#endif
