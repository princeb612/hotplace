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

#include <hotplace/sdk/crypto/cose/types.hpp>

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
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @example
     *          encrypt (handle, key, cose_aes128gcm, input, output);
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, const binary_t& input, binary_t& output);
    /**
     * @brief   encrypt ("Encrypt")
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in] at least one encryption algorithm
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @example
     *          algs.push_back(cose_aes256gcm); // one of cose_group_enc_xxx
     *          algs.push_back(cose_group_key_ecdhss_hmac); // cose_group_key_xxx
     *          encrypt (handle, key, algs, input, output);
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, const binary_t& input, binary_t& output);
    /**
     * @brief   encrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t* methods [in]
     * @param   size_t size_method [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @example
     *          cose_alg_t algs[] = { cose_aesccm_16_64_256 };
     *          cose.encrypt (handle, key, algs, 1, input, output);
     *          cose_alg_t algs2[] = { cose_aesccm_64_64_256, cose_group_key_ecdhss_hmac, cose_group_key_hkdf_aes, };
     *          encrypt (handle, key, algs2, 2, input, output);
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t* methods, size_t size_method, const binary_t& input, binary_t& output);
    /**
     * @brief   decrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out]
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     */
    return_t decrypt(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output, bool& result);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif
