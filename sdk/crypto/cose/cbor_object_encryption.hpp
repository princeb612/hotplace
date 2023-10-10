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

#include <hotplace/sdk/crypto/cose/cbor_object_signing_encryption.hpp>

namespace hotplace {
namespace crypto {

class cbor_object_encryption
{
public:
    cbor_object_encryption ();
    ~cbor_object_encryption ();

    /**
     * @brief encrypt
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param cose_alg_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     */
    return_t encrypt (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief encrypt
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param std::list<cose_alg_t> methods [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     */
    return_t encrypt (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief decrypt
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param binary_t const& input [in]
     * @param bool& result [out]
     */
    return_t decrypt (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result);

};

}
}  // namespace

#endif
