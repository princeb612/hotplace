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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNING__
#define __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNING__

#include <sdk/base.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>

namespace hotplace {
namespace crypto {

class cbor_object_signing {
   public:
    cbor_object_signing();
    ~cbor_object_signing();

    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t method [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, const binary_t& input, binary_t& output);
    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, const binary_t& input, binary_t& output);
    /**
     * @brief   mac
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, const binary_t& input, binary_t& output);

    /**
     * @brief   verify with kid
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in] CBOR
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify(cose_context_t* handle, crypto_key* key, const binary_t& input, bool& result);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif
