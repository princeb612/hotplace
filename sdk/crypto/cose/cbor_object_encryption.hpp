/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTENCRYPTION__
#define __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTENCRYPTION__

#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>

namespace hotplace {
namespace crypto {

class cbor_object_encryption {
   public:
    cbor_object_encryption();
    ~cbor_object_encryption();

    /**
     * @brief   encrypt ("Encrypt0")
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t method [in] must specify an encryption algoritm (see cose_group_enc_aesgcm/cose_group_enc_aesccm)
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief   encrypt ("Encrypt")
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in] at least one encryption algorithm
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief   decrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     */
    return_t decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, bool& result);

   protected:
    return_t dodecrypt(cose_context_t* handle, crypto_key* key, binary_t& output);
    return_t dodecrypt(cose_context_t* handle, crypto_key* key, cose_body_t* part, binary_t& output);
};

}  // namespace crypto
}  // namespace hotplace

#endif
