/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.12.11   Soo Han, Kim        implemented hmac (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_HASH__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_HASH__

#include <hotplace/sdk/crypto/crypto.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

class openssl_hash : public hash_t
{
public:
    /**
     * @brief constructor
     */
    openssl_hash ();
    /**
     * @brief destructor
     */
    virtual ~openssl_hash ();

    /**
     * @brief open (hash, HMAC)
     * @param hash_context_t** handle [out]
     * @param hash_algorithm_t alg [in]
     * @param const unsigned char* key [inopt]
     * @param unsigned keysize [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t open (hash_context_t** handle, hash_algorithm_t alg,
                           const unsigned char* key = nullptr,
                           unsigned keysize = 0);
    /**
     * @brief open (CMAC)
     * @param hash_context_t** handle [out]
     * @param crypt_algorithm_t alg [in]
     * @param const unsigned char* key [inopt]
     * @param unsigned keysize [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t open (hash_context_t** handle, crypt_algorithm_t alg,
                           const unsigned char* key = nullptr,
                           unsigned keysize = 0);
    /**
     * @brief close
     * @param hash_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    virtual return_t close (hash_context_t* handle);
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
    virtual return_t init (hash_context_t* handle);
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
    virtual return_t update (hash_context_t* handle, const byte_t* data, size_t datasize);
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
    virtual return_t finalize (hash_context_t* handle, byte_t** output, size_t* outputsize);
    /**
     * @brief finalize
     * @param hash_context_t* handle [in]
     * @param binary_t& output [out]
     */
    virtual return_t finalize (hash_context_t* handle, binary_t& output);
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
    virtual return_t free_data (void* data);
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
    virtual return_t hash (hash_context_t* handle, const byte_t* data, size_t datasize, binary_t& output);
    /**
     * @brief type
     * @return crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type ();
};


}
}  // namespace

#endif
