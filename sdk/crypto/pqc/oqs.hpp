/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_PQC_OQS__
#define __HOTPLACE_SDK_CRYPTO_PQC_OQS__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/pqc/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * key encapsulation mechanism
 *      Alice                                       Bob
 *      generate KEM key pair
 *      encode public key and distribute  --->
 *                                                  decode public key
 *                                        <---      encapsulate key, calc shared key
 *      calc shared secret
 */
class pqc_oqs {
   public:
    pqc_oqs();
    ~pqc_oqs();

    return_t open(oqs_context** context);
    return_t close(oqs_context* context);

    /**
     *  pqc.for_each(context, OSSL_OP_KEM, [&](const std::string& alg) -> void {});
     *  pqc.for_each(context, OSSL_OP_SIGNATURE, [&](const std::string& alg) -> void {});
     */
    return_t for_each(oqs_context* context, int opid, std::function<void(const std::string&)> func);
    return_t keygen(oqs_context* context, const std::string& alg, EVP_PKEY** pkey);
    /**
     * @brief   encode key
     * @param   oqs_context* context [in]
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t& pubkey [out]
     * @param   oqs_key_encoding_t encoding [in]
     * @param   const char* password [inopt]
     * @remarks
     *          password must not be nullptr in following cases
     *              oqs_key_encoding_encrypted_priv_pem
     *              oqs_key_encoding_encrypted_priv_der
     */
    return_t encode_key(oqs_context* context, EVP_PKEY* pkey, binary_t& pubkey, oqs_key_encoding_t encoding, const char* password = nullptr);
    /**
     * @param   oqs_context* context [in]
     * @param   EVP_PKEY** pkey [out]
     * @param   const binary_t& pubkey [in]
     * @param   oqs_key_encoding_t encoding [in]
     * @param   const char* password [inopt]
     * @remarks
     *          password must not be nullptr in following cases
     *              oqs_key_encoding_encrypted_priv_pem
     *              oqs_key_encoding_encrypted_priv_der
     */
    return_t decode_key(oqs_context* context, EVP_PKEY** pkey, const binary_t& pubkey, oqs_key_encoding_t encoding, const char* password = nullptr);

    return_t encapsule(oqs_context* context, EVP_PKEY* pkey, binary_t& capsulekey, binary_t& sharedsecret);
    return_t decapsule(oqs_context* context, EVP_PKEY* pkey, const binary_t& capsulekey, binary_t& sharedsecret);

    std::string nameof_encoding(oqs_key_encoding_t encoding);

   protected:
    struct oqs_key_encparams_t {
        int selection;
        const char* format;
        const char* structure;
        bool use_pass;
    };
    return_t get_params(oqs_key_encoding_t encoding, oqs_key_encparams_t& enc);
};

}  // namespace crypto
}  // namespace hotplace

#endif
