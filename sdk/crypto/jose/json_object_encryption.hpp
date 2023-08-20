/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7516 JSON Web Encryption (JWE)
 *  RFC 7518 JSON Web Algorithms (JWA)
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
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @remarks see json_object_signing_encryption::encrypt
     */
    return_t encrypt (jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t input, binary_t& output);
    /*
     * @brief decrypt
     * @param jose_context_t* handle
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t decrypt (jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t input, binary_t& output);
    /*
     * @brief decrypt
     * @param jose_context_t* handle
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param const char* kid [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t decrypt (jose_context_t* handle, jwe_t enc, jwa_t alg, const char* kid, binary_t input, binary_t& output);

protected:
    /*
     * @brief constraints
     * @param jwa_t alg [in]
     * @param EVP_PKEY* pkey [in]
     */
    return_t  check_constraints (jwa_t alg, EVP_PKEY* pkey);
};

}
}  // namespace

#endif
