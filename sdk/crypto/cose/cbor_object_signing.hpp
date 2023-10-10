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

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing_encryption.hpp>

namespace hotplace {
namespace crypto {

class cbor_object_signing {
   public:
    cbor_object_signing();
    ~cbor_object_signing();

    /**
     * @brief sign
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param cose_alg_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief sign
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param std::list<cose_alg_t> methods [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief verify with kid
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param binary_t const& input [in] CBOR
     * @param bool& result [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result);

   protected:
    /**
     * @brief   write
     * @param   cose_context_t* handle [in]
     * @param   uint8 tag [in]
     * @param   binary_t& signature [out]
     * @return  error code (see error.hpp)
     */
    return_t write_signature(cose_context_t* handle, uint8 tag, binary_t& signature);
    /*
     * @brief   verify
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const char* kid [in]
     * @param   cose_alg_t alg [in]
     * @param   binary_t const& tobesigned [in]
     * @param   binary_t const& signature [in]
     * @return  error code (see error.hpp)
     */
    return_t verify(cose_context_t* handle, crypto_key* key, const char* kid, cose_alg_t alg, binary_t const& tobesigned, binary_t const& signature);
    /**
     * @brief   tobesigned
     * @param   binary_t& tobesigned [out]
     * @param   uint8 tag [in]
     * @param   binary_t const& body_protected [in]
     * @param   binary_t const& sign_protected [in]
     * @param   binary_t const& aad [in]
     * @param   binary_t const& payload [in]
     * @return  error code (see error.hpp)
     */
    return_t compose_tobesigned(binary_t& tobesigned, uint8 tag, binary_t const& body_protected, binary_t const& sign_protected, binary_t const& aad,
                                binary_t const& payload);
};

}  // namespace crypto
}  // namespace hotplace

#endif
