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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNINGENCRYPTION__
#define __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNINGENCRYPTION__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
namespace crypto {

class cbor_object_signing_encryption
{
public:
    cbor_object_signing_encryption ();
    ~cbor_object_signing_encryption ();

    return_t open (cose_context_t** handle);
    return_t close (cose_context_t* handle);
    return_t reset (cose_context_t* handle);

    /**
     * @brief sign
     * @param cose_context_t* handle [inout]
     * @param crypto_key* key [in]
     * @param cose_alg_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief verify
     * @param cose_context_t* handle [inout]
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t const& output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result);
    /**
     * @brief verify with kid
     * @param cose_context_t* handle [inout]
     * @param crypto_key* key [in]
     * @param const char* kid [in]
     * @param crypt_sig_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t const& output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (cose_context_t* handle, crypto_key* key, const char* kid, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result);
};

}
}  // namespace

#endif
