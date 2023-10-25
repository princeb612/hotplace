/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2104 HMAC: Keyed-Hashing for Message Authentication
 *  RFC 4493 The AES-CMAC Algorithm
 *
 * Revision History
 * Date         Name                Description
 * 2009.12.11   Soo Han, Kim        implemented hmac (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_HASH__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_HASH__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/crypto.hpp>

namespace hotplace {
namespace crypto {

class openssl_hash : public hash_t {
   public:
    /**
     * @brief constructor
     */
    openssl_hash();
    /**
     * @brief destructor
     */
    virtual ~openssl_hash();
    /**
     * @brief open (hash, HMAC, CMAC)
     * @param hash_context_t** handle [out]
     * @param hash_algorithm_t alg [in]
     * @param const unsigned char* key [inopt]
     * @param unsigned keysize [inopt]
     * @return error code (see error.hpp)
     * @example
     *    binary_t hash_data;
     *    // hash
     *    hash.open(&handle, hash_algorithm_t::sha2_256);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // hash
     *    hash.open_byname(&handle, "sha256"); // wo key
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // hmac (HS256)
     *    hash.open(&handle, hash_algorithm_t::sha2_256, key, key_size);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // hmac (HS256)
     *    hash.open(&handle, "sha256", key, key_size);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // cmac (AES-128-CBC)
     *    hash.open(&handle, crypt_algorithm_t::aes128, key, key_size);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // cmac (AES-128-CBC)
     *    hash.open(&handle, "aes-128-cbc", key, key_size);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     */
    virtual return_t open_byname(hash_context_t** handle, const char* algorithm, const unsigned char* key = nullptr, unsigned keysize = 0);
    /**
     * @brief open (HMAC, CMAC)
     */
    virtual return_t open_byname(hash_context_t** handle, const char* algorithm, binary_t const& key);

    /**
     * @brief open (hash, HMAC)
     * @param hash_context_t** handle [out]
     * @param hash_algorithm_t alg [in]
     * @param const unsigned char* key [inopt]
     * @param unsigned keysize [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t open(hash_context_t** handle, hash_algorithm_t alg, const unsigned char* key = nullptr, unsigned keysize = 0);
    /**
     * @brief open (HMAC)
     */
    virtual return_t open(hash_context_t** handle, hash_algorithm_t alg, binary_t const& key);
    /**
     * @brief open (CMAC)
     * @param hash_context_t** handle [out]
     * @param crypt_algorithm_t alg [in]
     * @param crypt_mode_t mode [in]
     * @param const unsigned char* key [inopt]
     * @param unsigned keysize [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t open(hash_context_t** handle, crypt_algorithm_t alg, crypt_mode_t mode, const unsigned char* key, unsigned keysize);
    /**
     * @brief open (CMAC)
     */
    virtual return_t open(hash_context_t** handle, crypt_algorithm_t alg, crypt_mode_t mode, binary_t const& key);
    /**
     * @brief close
     * @param hash_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    virtual return_t close(hash_context_t* handle);
    /**
     * @brief init
     * @param hash_context_t* handle [in]
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t init(hash_context_t* handle);
    /**
     * @brief update
     * @param hash_context_t* handle [in]
     * @param const byte_t* data [in]
     * @param size_t datasize [in]
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t update(hash_context_t* handle, const byte_t* data, size_t datasize);
    virtual return_t update(hash_context_t* handle, binary_t const& input);
    /**
     * @brief hash
     * @param hash_context_t* handle [in]
     * @param byte_t** output [out]
     * @param size_t * outputsize [out] call free_data to free
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t finalize(hash_context_t* handle, byte_t** output, size_t* outputsize);
    /**
     * @brief finalize
     * @param hash_context_t* handle [in]
     * @param binary_t& output [out]
     */
    virtual return_t finalize(hash_context_t* handle, binary_t& output);
    /**
     * @brief free
     * @param void* data [in]
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t free_data(void* data);
    /**
     * @brief hash
     * @param hash_context_t* handle [in]
     * @param const byte_t* data [in]
     * @param size_t datasize [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks
     *        simply replace a serial method call (init, update, finalize, free_data in a low)
     */
    virtual return_t hash(hash_context_t* handle, const byte_t* data, size_t datasize, binary_t& output);

    /**
     * @brief type
     * @return crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type();
};

return_t digest(const char* alg, binary_t const& input, binary_t& output);
return_t digest(hash_algorithm_t alg, binary_t const& input, binary_t& output);
return_t hmac(const char* alg, binary_t const& key, binary_t const& input, binary_t& output);
return_t hmac(hash_algorithm_t alg, binary_t const& key, binary_t const& input, binary_t& output);
/**
 * @brief   AES Cipher-Based Message Authentication Code (AES-CMAC)
 * @desc    RFC 4493 The AES-CMAC Algorithm
 *          see also kdf_ckdf
 * @remarks not the same algorithm AES-CBC-MAC
 *          see also RFC 8152 9.2.  AES Message Authentication Code (AES-CBC-MAC)
 */
return_t cmac(const char* alg, binary_t const& key, binary_t const& input, binary_t& output);
return_t cmac(crypt_algorithm_t alg, crypt_mode_t mode, binary_t const& key, binary_t const& input, binary_t& output);

}  // namespace crypto
}  // namespace hotplace

#endif
