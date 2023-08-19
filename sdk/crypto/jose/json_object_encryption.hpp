/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_ENCRYPTION__
#define __HOTPLACE_SDK_CRYPTO_JOSE_ENCRYPTION__

#include <hotplace/sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

class json_object_encryption
{
public:
    json_object_encryption ();
    ~json_object_encryption ();

    /*
     * @brief encrypt
     * @param jose_context_t* handle [in] see json_object_signing_encryption::open and close
     * @param crypt_enc_t enc [in]
     * @param crypt_alg_t alg [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @remarks see json_object_signing_encryption::encrypt
     */
    return_t encrypt (jose_context_t* handle, crypt_enc_t enc, crypt_alg_t alg, binary_t input, binary_t& output);
    /*
     * @brief decrypt
     * @param jose_context_t* handle
     * @param crypt_enc_t enc [in]
     * @param crypt_alg_t alg [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t decrypt (jose_context_t* handle, crypt_enc_t enc, crypt_alg_t alg, binary_t input, binary_t& output);
    /*
     * @brief decrypt
     * @param jose_context_t* handle
     * @param crypt_enc_t enc [in]
     * @param crypt_alg_t alg [in]
     * @param const char* kid [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t decrypt (jose_context_t* handle, crypt_enc_t enc, crypt_alg_t alg, const char* kid, binary_t input, binary_t& output);

protected:
    /*
     * @brief constraints
     * @param crypt_alg_t alg [in]
     * @param EVP_PKEY* pkey [in]
     */
    return_t  check_constraints (crypt_alg_t alg, EVP_PKEY* pkey);
};

}
}  // namespace

#endif
