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

namespace hotplace {
namespace crypto {

class cbor_object_signing
{
public:
    cbor_object_signing ();
    ~cbor_object_signing ();

    /**
     * @brief sign
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output);
    /**
     * @brief sign and return signature and kid
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @param std::string& kid [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output, std::string& kid);
    /**
     * @brief verify
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t const& output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result);
    /**
     * @brief verify with kid
     * @param crypto_key* key [in]
     * @param const char* kid [in]
     * @param crypt_sig_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t const& output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (crypto_key* key, const char* kid, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result);
};

}
}  // namespace

#endif
