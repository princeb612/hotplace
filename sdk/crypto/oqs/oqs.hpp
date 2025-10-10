/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OQS_OQS__
#define __HOTPLACE_SDK_CRYPTO_OQS_OQS__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/oqs/types.hpp>

namespace hotplace {
namespace crypto {

enum oqs_alg_flag_t {
    oqs_alg_oid_registered = 1,
};

/**
 * key encapsulation mechanism
 *      Alice                                       Bob
 *      generate KEM key pair
 *      encode public key and distribute  --->
 *                                                  decode public key
 *                                        <---      encapsulate key
 *                                                  calc shared key
 *      decapsulate
 *      calc shared secret
 *
 *      generate DSA key pair
 *      encode public key and distribute  --->
 *                                                  decode public key
 *      sign message                      --->      verify message
 */
class pqc_oqs {
   public:
    pqc_oqs();
    ~pqc_oqs();

    return_t open(oqs_context** context);
    return_t close(oqs_context* context);

    /**
     * @example
     *          pqc.for_each(context, OSSL_OP_KEM, [&](const std::string& alg, int flags) -> void {});
     *          pqc.for_each(context, OSSL_OP_SIGNATURE, [&](const std::string& alg, int flags) -> void {});
     */
    return_t for_each(oqs_context* context, int opid, std::function<void(const std::string&, int)> func);
    return_t keygen(EVP_PKEY** pkey, oqs_context* context, const std::string& alg);
    /**
     * @brief   encode key
     * @param   oqs_context* context [in]
     * @param   const EVP_PKEY* pkey [in]
     * @param   binary_t& keydata [out]
     * @param   key_encoding_t encoding [in]
     * @param   const char* password [inopt]
     * @remarks
     *          password must not be nullptr in following cases
     *              key_encoding_encrypted_priv_pem
     *              key_encoding_encrypted_priv_der
     */
    return_t encode(oqs_context* context, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* password = nullptr);
    /**
     * @param   oqs_context* context [in]
     * @param   EVP_PKEY** pkey [out]
     * @param   const binary_t& keydata [in]
     * @param   key_encoding_t encoding [in]
     * @param   const char* password [inopt]
     * @remarks
     *          password must not be nullptr in following cases
     *              key_encoding_encrypted_priv_pem
     *              key_encoding_encrypted_priv_der
     */
    return_t decode(oqs_context* context, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* password = nullptr);

    return_t encapsule(oqs_context* context, EVP_PKEY* pkey, binary_t& capsulekey, binary_t& sharedsecret);
    return_t decapsule(oqs_context* context, EVP_PKEY* pkey, const binary_t& capsulekey, binary_t& sharedsecret);

    return_t sign(oqs_context* context, EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    return_t verify(oqs_context* context, EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif
