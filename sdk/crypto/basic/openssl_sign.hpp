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

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLSIGN__
#define __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLSIGN__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto.hpp>

namespace hotplace {
namespace crypto {

/**
 * @remarks
 *
 *          if (sign_flag_format_der & flags) { ... }
 *              // handle DER
 *           } else {
 *              // sign_flag_format_der is not set
 *              // handle R || S
 *          }
 */
enum sign_flag_t : uint32 {
    /**
     * @brief   R || S signature (ECDSA, DSA)
     */
    sign_flag_format_rs = 0,
    /**
     * @brief   DER signature (ECDSA, DSA)
     */
    sign_flag_format_der = 1,
};

/**
 * @brief openssl_sign
 */
class openssl_sign {
   public:
    /**
     * @brief constructor
     */
    openssl_sign();
    /**
     * @brief destructor
     */
    virtual ~openssl_sign();

    /**
     * @biref   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   crypt_sig_t mode [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& signature [out]
     * @param   uint32 flags [inopt]
     */
    return_t sign(const EVP_PKEY* pkey, crypt_sig_t mode, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign(const EVP_PKEY* pkey, crypt_sig_t mode, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /**
     * @biref   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   crypt_sig_t mode [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @param   uint32 flags [inopt]
     */
    return_t verify(const EVP_PKEY* pkey, crypt_sig_t mode, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify(const EVP_PKEY* pkey, crypt_sig_t mode, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);

    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t sign_digest(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign_digest(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t sign_hash(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign_hash(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    RS256, RS384, RS512
     */
    return_t sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @param   uint32 flags [inopt]
     * @desc    ES256, ES384, ES512, ES256K
     */
    return_t sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    PS256, PS384, PS512
     */
    return_t sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, int saltlen);
    return_t sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    return_t sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, int saltlen);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    EdDSA
     */
    return_t sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    return_t sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t verify_digest(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify_digest(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t verify_hash(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify_hash(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    RS256, RS384, RS512
     */
    return_t verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature,
                                  uint32 flags = 0);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @param   uint32 flags [inopt]
     * @desc    ES256, ES384, ES512, ES256K
     */
    return_t verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    PS256, PS384, PS512
     */
    return_t verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, int saltlen);
    return_t verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);
    return_t verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, int saltlen);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   const binary_t& input [in]
     * @param   const binary_t& signature [in]
     * @desc    EdDSA
     */
    return_t verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    return_t verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);

    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const binary_t& input
     * @param binary_t& r
     * @param binary_t& s
     */
    return_t sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& r, binary_t& s);
    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const byte_t* stream
     * @param size_t size
     * @param binary_t& r
     * @param binary_t& s
     */
    return_t sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& r, binary_t& s);
    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const binary_t& input
     * @param const binary_t& r
     * @param const binary_t& s
     */
    return_t verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& r, const binary_t& s);
    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const byte_t* stream
     * @param size_t size
     * @param const binary_t& r
     * @param const binary_t& s
     */
    return_t verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& r, const binary_t& s);

    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const binary_t& input
     * @param binary_t& signature
     */
    return_t sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags = 0);
    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const byte_t* stream
     * @param size_t size
     * @param binary_t& signature
     */
    return_t sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags = 0);
    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const binary_t& input
     * @param const binary_t& signature
     */
    return_t verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags = 0);
    /**
     * @brief sign
     * @param const EVP_PKEY* pkey
     * @param hash_algorithm_t hashalg
     * @param const byte_t* stream
     * @param size_t size
     * @param const binary_t& signature
     */
    return_t verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags = 0);
};

/**
 * @brief ASN.1 DER
 * @param const binary_t& r
 * @param const binary_t& s
 * @param binary_t& asn1der
 */
return_t rs2der(const binary_t& r, const binary_t& s, binary_t& asn1der);
/**
 * @brief ASN.1 DER
 * @param const binary_t& asn1der
 * @param uint16 unitsize
 * @param binary_t& r
 * @param binary_t& s
 */
return_t der2rs(const binary_t& asn1der, uint16 unitsize, binary_t& r, binary_t& s);
/**
 * @brief R || S
 * @param const binary_t& sig
 * @param binary_t& r
 * @param binary_t& s
 */
return_t sig2rs(const binary_t& sig, binary_t& r, binary_t& s);
/**
 * @brief R || S
 * @param const binary_t& r
 * @param const binary_t& s
 * @param uint16 unitsize
 * @param binary_t& signature
 */
return_t rs2sig(const binary_t& r, const binary_t& s, uint16 unitsize, binary_t& signature);
/**
 * @brief R || S
 * @param const binary_t& asn1der
 * @param uint16 unitsize
 * @param binary_t& signature
 */
return_t der2sig(const binary_t& asn1der, uint16 unitsize, binary_t& signature);
/**
 * @brief R || S to ASN.1 DER
 * @param const binary_t& signature
 * @param binary_t& asn1der
 */
return_t sig2der(const binary_t& signature, binary_t& asn1der);

}  // namespace crypto
}  // namespace hotplace

#endif
