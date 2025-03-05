/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6238 TOTP: Time-Based One-Time Password Algorithm
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_TIMEOTP__
#define __HOTPLACE_SDK_CRYPTO_BASIC_TIMEOTP__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

class time_otp {
   public:
    time_otp();
    ~time_otp();
    /**
     * @brief open
     * @param otp_context_t** handle [out]
     * @param unsigned int digit_length [in]
     * @param time_t interval [in] 0 is ignored
     * @param hash_algorithm_t algorithm [in]
     * @param const byte_t* key_data [in]
     * @param size_t key_size [in]
     * @return error code (see error.hpp)
     * @example
     *        otp.open(&handle, 8, 30, HASH_ALGORITHM_SHA_512, key, keysize);
     *        otp.close(handle);
     */
    uint32 open(otp_context_t** handle, unsigned int digit_length, time_t interval, hash_algorithm_t algorithm, const byte_t* key_data, size_t key_size);
    /**
     * @brief close
     * @param otp_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    uint32 close(otp_context_t* handle);
    /**
     * @brief close
     * @param otp_context_t* handle [in]
     * @param time64_t time [in]
     * @param uint32& code [out]
     * @return error code (see error.hpp)
     * @example
     *        otp.get(handle, time, code);
     */
    uint32 get(otp_context_t* handle, time64_t time, uint32& code);
    /**
     * @brief close
     * @param otp_context_t* handle [in]
     * @param time64_t time [in]
     * @param uint32 code [in]
     * @return error code (see error.hpp)
     */
    uint32 verify(otp_context_t* handle, time64_t time, uint32 code);
};

}  // namespace crypto
}  // namespace hotplace

#endif
