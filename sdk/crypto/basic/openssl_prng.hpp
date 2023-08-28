/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_PRNG__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_PRNG__

#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief random number generator
 */
class openssl_prng
{
public:
    openssl_prng ();
    ~openssl_prng ();

    /**
     * @brief rand32
     * @return random-generated int32 value
     */
    int32 rand32 ();
    /**
     * @brief rand64
     * @return random-generated int32 value
     */
    int64 rand64 ();
    /**
     * @brief fill buffer with random-generated n-bytes data
     * @param unsigned char* buf [out] not nullptr
     * @param size_t size [in] size > 0
     * @return error code (see error.hpp)
     */
    return_t random (unsigned char* buf, size_t size);
    return_t random (binary_t& buffer, size_t size);
    return_t random (uint32& i, uint32 mask = (uint32) ~1);
};


}
}  // namespace

#endif
