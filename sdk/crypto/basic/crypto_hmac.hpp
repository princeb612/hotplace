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

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOHMAC__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOHMAC__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>

namespace hotplace {
namespace crypto {

class crypto_hmac {
    friend class crypto_hmac_builder;

   public:
    ~crypto_hmac();

    /**
     * @sample
     *      crypto_hmac_builder builder;
     *      auto hmac = builder.set(sha2_256).set(key).build();
     *      if (hmac) {
     *          hmac->mac(key, mesage, size, md);
     *      }
     */
    return_t mac(const binary_t& input, binary_t& output);
    return_t mac(const byte_t* stream, size_t size, binary_t& output);

    /**
     * @sample
     *      crypto_hmac_builder builder;
     *      auto hmac = builder.set(sha2_256).set(key).build();
     *      if (hmac) {
     *          *hmac << "hello" << "world";
     *          hmac->finalize(md);
     *          hmac->release();
     *      }
     */
    crypto_hmac& init();
    crypto_hmac& operator<<(const char* message);
    crypto_hmac& operator<<(const binary_t& message);
    crypto_hmac& update(const binary_t& message);
    crypto_hmac& update(const byte_t* stream, size_t size);
    template <typename T>
    crypto_hmac& update(T value, std::function<T(const T&)> fn = nullptr);
    crypto_hmac& update(uint8 value, std::function<uint8(const uint8&)> fn = nullptr);
    crypto_hmac& update(uint16 value, std::function<uint16(const uint16&)> fn = nullptr);
    crypto_hmac& update(uint32 value, std::function<uint32(const uint32&)> fn = nullptr);
    crypto_hmac& update(uint64 value, std::function<uint64(const uint64&)> fn = nullptr);
    crypto_hmac& digest(binary_t& md);
    crypto_hmac& finalize(binary_t& md);

    hash_algorithm_t get_digest();

    void addref();
    void release();

   protected:
    crypto_hmac(hash_algorithm_t alg, const binary_t& key);

   private:
    t_shared_reference<crypto_hmac> _shared;
    hash_context_t* _handle;
    hash_algorithm_t _alg;
    binary_t _key;
};

class crypto_hmac_builder {
   public:
    crypto_hmac_builder();
    crypto_hmac_builder& set(hash_algorithm_t alg);
    crypto_hmac_builder& set(const binary_t& key);
    crypto_hmac* build();

   protected:
   private:
    hash_algorithm_t _alg;
    binary_t _key;
};

}  // namespace crypto
}  // namespace hotplace

#endif
