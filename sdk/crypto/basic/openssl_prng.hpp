/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLPRNG__
#define __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLPRNG__

#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief pseudo random number generator
 */
class openssl_prng {
   public:
    openssl_prng();
    ~openssl_prng();

    /**
     * @brief rand32
     * @return random-generated int32 value
     */
    int32 rand32();
    /**
     * @brief rand64
     * @return random-generated int32 value
     */
    int64 rand64();
    /**
     * @brief fill buffer with random-generated n-bytes data
     * @param unsigned char* buf [out] not nullptr
     * @param size_t size [in] size > 0
     * @return error code (see error.hpp)
     */
    return_t random(unsigned char* buf, size_t size);
    return_t random(binary_t& buffer, size_t size);
    return_t random(uint32& i, uint32 mask = (uint32)~1);

    /**
     * @brief   nonce, token
     * @param   size_t size [in] size of byte stream
     * @param   encoding_t expr [in]
     * @param   bool usetime [inopt] default false. if true, prefix time
     */
    std::string rand(size_t size, encoding_t expr, bool usetime = false);

    /**
     * @brief   nonce
     * @remarks minimum size is 8
     * @example
     *          auto nc = std::move(prng.nonce(20, encoding_t::encoding_base16));
     */
    std::string nonce(size_t size, encoding_t expr);
    /**
     * @brief   token
     * @remarks minimum size is 8
     * @example
     *          auto token = std::move(prng.token(20, encoding_t::encoding_base64url));
     */
    std::string token(size_t size, encoding_t expr);
};

}  // namespace crypto
}  // namespace hotplace

#endif
