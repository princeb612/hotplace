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

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPTO_HASH__
#define __HOTPLACE_SDK_CRYPTO_CRYPTO_HASH__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>

namespace hotplace {
namespace crypto {

/**
 * @sample
 *          crypto_hash hash(sha2_256);
 *          hash.digest((byte_t*)"hello", 5, hash1);  // hash1 = sha2_256("hello")
 *          hash.digest((byte_t*)" ", 1, hash2);      // hash2 = sha2_256(" ")
 *          hash.digest((byte_t*)"world", 5, hash3);  // hash3 = sha2_256("world")
 */
class crypto_hash {
   public:
    crypto_hash(hash_algorithm_t alg);

    return_t digest(const binary_t& message, binary_t& result);
    return_t digest(const byte_t* stream, size_t size, binary_t& result);

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<crypto_hash> _shared;
    hash_algorithm_t _alg;
};

/**
 * @sample
 *          auto hash = builder.set(sha2_256).build();
 *          if (hash) {
 *              hash->digest(message1, digest1); // digest1 = sha2_256(message1)
 *              hash->digest(message2, digest2); // digest2 = sha2_256(message2)
 *              hash->digest(message3, digest3); // digest3 = sha2_256(message3)
 *              hash->release();
 *          }
 */
class crypto_hash_builder {
   public:
    crypto_hash_builder();
    crypto_hash* build();

    crypto_hash_builder& set(hash_algorithm_t alg);

   protected:
   private:
    hash_algorithm_t _alg;
};

}  // namespace crypto
}  // namespace hotplace

#endif
