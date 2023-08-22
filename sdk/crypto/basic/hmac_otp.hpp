/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_HMACOTP__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_HMACOTP__

#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

class hmac_otp
{
public:
    hmac_otp ();
    ~hmac_otp ();
    /*
     * @brief open
     * @param otp_context_t** handle [in]
     * @param unsigned int digit_length [in]
     * @param hash_algorithm_t algorithm [in]
     * @param const byte_t* key_data [in]
     * @param size_t key_size [in]
     * @return error code (see error.hpp)
     * @sample
     *        uint32 code = 0;
     *        otp.open (&handle, 6, HASH_ALGORITHM_SHA_256, key, keysize);
     *        otp.get (handle, code);
     *        printf ("%06u", code);
     *        otp.close(handle);
     */
    uint32 open (otp_context_t** handle, unsigned int digit_length, hash_algorithm_t algorithm, const byte_t* key_data, size_t key_size);
    /*
     * @brief close
     * @param otp_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    uint32 close (otp_context_t* handle);
    /*
     * @brief set count
     * @param otp_context_t* handle [in]
     * @param uint32 count [in]
     * @return error code (see error.hpp)
     * @sample
     *        otp.set(handle, 100);
     *        otp.get(handle, code); // otp.get(handle, 100, code) - same expression
     *        otp.get(handle, code); // otp.get(handle, 101, code) - same expression
     */
    uint32 set (otp_context_t* handle, uint32 count);
    /*
     * @brief get code
     * @param otp_context_t* handle [in]
     * @param uint32& code [out]
     * @return error code (see error.hpp)
     * @remarks
     *        internal counter is increased automatically
     */
    uint32 get (otp_context_t* handle, uint32& code);
    /*
     * @brief set count and get code
     * @param otp_context_t* handle [in]
     * @param uint32 counter [in]
     * @param uint32& code [out]
     * @return error code (see error.hpp)
     * @sample
     *        otp.get(handle, 100, code);
     */
    uint32 get (otp_context_t* handle, uint32 counter, uint32& code);
    /*
     * @brief set count and get code
     * @param otp_context_t* handle [in]
     * @param binary_t counter [in]
     * @param uint32& code [out]
     * @return error code (see error.hpp)
     */
    uint32 get (otp_context_t* handle, binary_t counter, uint32& code);
    /*
     * @brief verify
     * @param otp_context_t* handle [in]
     * @param uint32 counter [in]
     * @param uint32 code [in]
     * @return error code (see error.hpp)
     */
    uint32 verify (otp_context_t* handle, uint32 counter, uint32 code);
};

}
}  // namespace

#endif
