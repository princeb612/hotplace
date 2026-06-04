/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_hmac.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOHMAC__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOHMAC__

#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

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
    /**
     * update(int8)
     * update(int16)
     * update(int32)
     * update(int64)
     * update(int128)
     * update(int16, hton16)
     * update(int32, hton32)
     * update(int64, hton64)
     * update(int128, hton128)
     * update(uint8)
     * update(uint16)
     * update(uint32)
     * update(uint64)
     * update(uint128)
     * update(uint16, hton16)
     * update(uint32, hton32)
     * update(uint64, hton64)
     * update(uint128, hton128)
     */
    template <typename T, typename transformer_t, typename = typename std::enable_if<custom::is_integral<T>::value>::type>
    crypto_hmac& update(T value, transformer_t func) {
        using make_unsigned_t = typename custom::make_unsigned<T>::type;

        make_unsigned_t unsigned_value = static_cast<make_unsigned_t>(value);
        make_unsigned_t final_value = (func) ? func(unsigned_value) : unsigned_value;

        openssl_hash hash;
        hash.update(_handle, (byte_t*)&final_value, sizeof(T));
        return *this;
    }

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
