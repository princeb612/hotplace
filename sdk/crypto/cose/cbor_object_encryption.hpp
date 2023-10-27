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
     * @brief   encrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t method [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief   encrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in]
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
    /**
     * @brief   mac
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t method [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t mac(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief   mac
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief   verify with kid
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   binary_t const& input [in]
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     */
    return_t verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result);

   protected:
    return_t dodecrypt(cose_context_t* handle, crypto_key* key, binary_t& output);
    /**
     * @brief cek into handle->binarymap[cose_param_t::cose_param_cek]
     */
    return_t process_recipient(cose_context_t* handle, crypto_key* key, cose_parts_t* item);
};

}  // namespace crypto
}  // namespace hotplace

#endif
