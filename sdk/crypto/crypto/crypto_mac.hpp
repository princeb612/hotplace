/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPTO_MAC__
#define __HOTPLACE_SDK_CRYPTO_CRYPTO_MAC__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>

namespace hotplace {
namespace crypto {

class crypto_hmac {
    friend class crypto_hmac_builder;

   public:
    return_t mac(const binary_t& key, const binary_t& input, binary_t& output);
    return_t mac(const binary_t& key, const byte_t* stream, size_t size, binary_t& output);
    hash_algorithm_t get_digest();

    void addref();
    void release();

   protected:
    crypto_hmac(hash_algorithm_t alg);

    t_shared_reference<crypto_hmac> _shared;
    hash_algorithm_t _alg;
};

class crypto_hmac_builder {
   public:
    crypto_hmac_builder();
    crypto_hmac_builder& set(hash_algorithm_t alg);
    crypto_hmac* build();

   protected:
    hash_algorithm_t _alg;
};

}  // namespace crypto
}  // namespace hotplace

#endif
