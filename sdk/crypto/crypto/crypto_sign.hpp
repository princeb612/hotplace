/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPTO_SIGN__
#define __HOTPLACE_SDK_CRYPTO_CRYPTO_SIGN__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/crypto/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief   sign
 * @sample
 *          // rsa_pkcs1_sha256
 *          auto sign = builder.set_scheme(sign_scheme_rsa_pkcs1).set_digest(sha2_256).build();
 *          if (sign) {
 *              ret = sign->verify(pkey, input, signature);
 *              sign->release();
 *          }
 *
 *          // rsa_pss_rsae_sha256
 *          auto sign = builder.set_scheme(crypt_sig_rsassa_pkcs15).set_digest(sha2_256).build();
 *          if (sign) {
 *              ret = sign->verify(pkey, input, signature);
 *              sign->release();
 *          }
 *
 *          // rsa_pkcs1_sha256
 *          crypto_sign_rsa_pkcs1 rsa_pkcs1_sha256(sha2_256);
 *          rsa_pkcs1_sha256.verify(pkey, input, signature);
 *
 *          // rsa_pss_rsae_sha384
 *          crypto_sign_rsa_pkcs1 rsa_pkcs1_sha384(sha2_384);
 *          rsa_pkcs1_sha384.verify(pkey, input, signature);
 *
 *          // rsa_pss_rsae_sha512
 *          crypto_sign_rsa_pkcs1 rsa_pkcs1_sha512(sha2_512);
 *          rsa_pkcs1_sha512.verify(pkey, input, signature);
 */
class crypto_sign_builder {
   public:
    crypto_sign_builder();

    /**
     * @sample
     */
    crypto_sign* build();
    crypt_sig_type_t get_scheme();
    hash_algorithm_t get_digest();

    /**
     * @sample
     *          auto sign = builder.set_scheme(crypt_sig_rsassa_pkcs15).set_digest(sha2_256).build();
     */
    crypto_sign_builder& set_scheme(crypt_sig_type_t scheme);
    crypto_sign_builder& set_digest(hash_algorithm_t hashalg);

    /**
     * @sample
     *          // 0x0804 rsa_pss_rsae_sha256
     *          auto sign = builder.tls_sign_scheme(0x0804).build();
     */
    crypto_sign_builder& set_tls_sign_scheme(uint16 scheme);

   protected:
    crypt_sig_type_t _scheme;
    uint16 _hashalg;
};

class crypto_sign {
    friend class crypto_sign_builder;

   public:
    virtual return_t sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature) = 0;
    virtual return_t verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature) = 0;
    virtual return_t sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature) = 0;
    virtual return_t verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature) = 0;

    void set_saltlen(int saltlen);  // RSA PSS (-1)

    crypt_sig_type_t get_scheme();
    hash_algorithm_t get_digest();
    int get_saltlen();

    void addref();
    void release();

   protected:
    crypto_sign(hash_algorithm_t hashalg);
    void set_scheme(crypt_sig_type_t scheme);

   private:
    t_shared_reference<crypto_sign> _shared;
    crypt_sig_type_t _scheme;
    hash_algorithm_t _hashalg;
    int _saltlen;
};

class crypto_sign_rsa_pkcs1 : public crypto_sign {
   public:
    crypto_sign_rsa_pkcs1(hash_algorithm_t hashalg);

    virtual return_t sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
    virtual return_t sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature);
};

class crypto_sign_ecdsa : public crypto_sign {
   public:
    crypto_sign_ecdsa(hash_algorithm_t hashalg);

    virtual return_t sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
    virtual return_t sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature);
};

class crypto_sign_rsa_pss : public crypto_sign {
   public:
    crypto_sign_rsa_pss(hash_algorithm_t hashalg);

    virtual return_t sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
    virtual return_t sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature);
};

class crypto_sign_eddsa : public crypto_sign {
   public:
    crypto_sign_eddsa(hash_algorithm_t hashalg = hash_alg_unknown);

    virtual return_t sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
    virtual return_t sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature);
};

class crypto_sign_dsa : public crypto_sign {
   public:
    crypto_sign_dsa(hash_algorithm_t hashalg = hash_alg_unknown);

    virtual return_t sign(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
    virtual return_t sign(const EVP_PKEY* pkey, const binary_t& input, binary_t& signature);
    virtual return_t verify(const EVP_PKEY* pkey, const binary_t& input, const binary_t& signature);
};

// not implemented
// class crypto_sign_rsa_x931 : public crypto_sign {};

}  // namespace crypto
}  // namespace hotplace

#endif
