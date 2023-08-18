/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPT__
#define __HOTPLACE_SDK_CRYPTO_CRYPT__

#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

class crypt_interface
{
public:
    /**
     * @brief create a context handle
     * @param crypt_context_t** handle [out]
     * @param crypt_symmetric_t algorithm [in]
     * @param crypt_mode_t mode [in]
     * @param const unsigned char* key [in]
     * @param unsigned size_key [in]
     * @param const unsigned char* iv [in]
     * @param unsigned size_iv [in]
     * @return error code (see error.h)
     * @sample
     *        crypt_context_t* handle = nullptr;
     *        crypt.open(&handle, crypt_symmetric_t::aes256, crypt_mode_t::cbc, key, size_key, iv, size_iv);
     *        crypt.close(handle);
     */
    virtual return_t open (crypt_context_t** handle, crypt_symmetric_t algorithm, crypt_mode_t mode, const unsigned char* key, unsigned size_key, const unsigned char* iv, unsigned size_iv) = 0;
    /**
     * @brief destroy a context handle
     * @param crypt_context_t* handle [in]
     * @return error code (see error.h)
     */
    virtual return_t close (crypt_context_t* handle) = 0;
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param unsigned char** data_encrypted [out]
     * @param size_t* size_encrypted [out]
     * @return error code (see error.h)
     * @sample
     *        crypt.encrypt(handle, data_plain, size_plain, &data_encrypted, &size_encrypted);
     *        crypt.free_data(data_encrypted);
     */
    virtual return_t encrypt (crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, unsigned char** data_encrypted, size_t* size_encrypted) = 0;
    virtual return_t encrypt (crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, binary_t& out) = 0;
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param unsigned char** data_plain [out]
     * @param size_t* size_plain [out]
     * @return error code (see error.h)
     * @sample
     *        crypt.decrypt(handle, data_encrypted, size_encrypted, &data_decrypted, &size_decrypted);
     *        crypt.free_data(data_decrypted);
     */
    virtual return_t decrypt (crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, unsigned char** data_plain, size_t* size_plain) = 0;
    virtual return_t decrypt (crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, binary_t& out) = 0;

    /**
     * @brief free
     * @param unsigned char* data [in]
     * @return error code (see error.h)
     */
    virtual return_t free_data (unsigned char* data) = 0;

    /**
     * @brief crypt_poweredby_t
     * @return see crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type () = 0;
    /*
     * @brief query
     * @param crypt_context_t* handle [in]
     * @param size_t cmd [in] 1 key size, 2 iv size
     * @param size_t& value [out]
     * @return error code (see error.h)
     */
    virtual return_t query (crypt_context_t* handle, size_t cmd, size_t& value) = 0;

protected:
};

class hash_interface
{
public:
    /**
     * @brief constructor
     */
    hash_interface ()
    {
    }
    /**
     * @brief destructor
     */
    virtual ~hash_interface ()
    {
    }

    virtual return_t open_byname (hash_context_t** handle, const char* algorithm,
                                  const unsigned char* key = nullptr,
                                  unsigned keysize = 0)
    {
        return_t ret = errorcode_t::success;
        hash_algorithm_t alg;

        __try2
        {
            if (nullptr == algorithm) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }

            if (0 == strcasecmp (algorithm, "md4")) {
                alg = hash_algorithm_t::md4;
            } else if (0 == strcasecmp (algorithm, "md5")) {
                alg = hash_algorithm_t::md5;
            } else if (0 == strcasecmp (algorithm, "sha1")) {
                alg = hash_algorithm_t::sha1;
            } else if (0 == strcasecmp (algorithm, "ripemd160")) {
                alg = hash_algorithm_t::ripemd160;
            } else if (0 == strcasecmp (algorithm, "sha224")) {
                alg = hash_algorithm_t::sha2_224;
            } else if (0 == strcasecmp (algorithm, "sha256")) {
                alg = hash_algorithm_t::sha2_256;
            } else if (0 == strcasecmp (algorithm, "sha384")) {
                alg = hash_algorithm_t::sha2_384;
            } else if (0 == strcasecmp (algorithm, "sha512")) {
                alg = hash_algorithm_t::sha2_512;
            } else if (0 == strcasecmp (algorithm, "whirlpool")) {
                alg = hash_algorithm_t::whirlpool;
            } else {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            ret = open (handle, alg, key, keysize);
        }
        __finally2
        {
            // do nothing
        }
        return ret;
    }
    /*
     * @brief expect hash size
     * @param hash_algorithm_t algorithm [in]
     * @param size_t& digest_size [out]
     * @return error code (see error.h)
     */
    virtual return_t get_digest_size (hash_algorithm_t algorithm, size_t& digest_size)
    {
        return_t ret = errorcode_t::success;

        digest_size = 0;

        switch (algorithm) {
            case hash_algorithm_t::md4:
                digest_size = (128 >> 3);
                break;
            case hash_algorithm_t::md5:
                digest_size = (128 >> 3);
                break;
            case hash_algorithm_t::sha1:
                digest_size = (160 >> 3);
                break;
            case hash_algorithm_t::ripemd160:
                digest_size = 20; // RIPEMD160_DIGEST_LENGTH
                break;
            case hash_algorithm_t::sha2_256:
                digest_size = (256 >> 3);
                break;
            case hash_algorithm_t::sha2_384:
                digest_size = (384 >> 3);
                break;
            case hash_algorithm_t::sha2_512:
                digest_size = (512 >> 3);
                break;
            default:
                ret = errorcode_t::invalid_parameter;
                break;
        }

        return ret;
    }

    /**
     * @brief open
     * @param hash_context_t** handle [out]
     * @param hash_algorithm_t alg [in]
     * @param const unsigned char* key [inopt]
     * @param unsigned keysize [inopt]
     * @return error code (see error.h)
     * @sample
     *    binary_t hash_data;
     *    // hash
     *    hash.open(&handle, hash_algorithm_t::sha2_256);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // hmac (HS256)
     *    hash.open(&handle, hash_algorithm_t::sha2_256, key, key_size);
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     *    // hash
     *    hash.open_byname(&handle, "sha256");
     *    hash.hash(handle, source, source_size, hash_data);
     *    hash.close(handle)
     */
    virtual return_t open (hash_context_t** handle, hash_algorithm_t alg,
                           const unsigned char* key = nullptr,
                           unsigned keysize         = 0)= 0;
    /**
     * @brief close
     * @param hash_context_t* handle [in]
     * @return error code (see error.h)
     */
    virtual return_t close (hash_context_t* handle) = 0;
    /*
     * @brief initialize a new digest operation
     * @param hash_context_t* handle [in]
     * @return error code (see error.h)
     * @sample
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t init (hash_context_t* handle) = 0;
    /**
     * @brief update
     * @param hash_context_t* handle [in]
     * @param byte_t* data [out]
     * @param size_t datasize [in]
     * @return error code (see error.h)
     * @sample
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t update (hash_context_t* handle, byte_t* data, size_t datasize) = 0;
    /**
     * @brief get
     * @param hash_context_t* handle [in]
     * @param byte_t** data [out]
     * @param size_t * datasize [out] call free_data to free
     * @return error code (see error.h)
     * @sample
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t finalize (hash_context_t* handle, byte_t** data, size_t* datasize) = 0;
    /*
     * @brief finalize
     * @param hash_context_t* handle [in]
     * @param binary_t& hash [out]
     */
    virtual return_t finalize (hash_context_t* handle, binary_t& hash) = 0;
    /**
     * @brief get
     * @param hash_context_t* handle [in]
     * @param byte_t* source_data [in]
     * @param size_t source_size [in]
     * @param binary_t& output [out]
     * @return error code (see error.h)
     * @sample
     *        hash.hash(handle, input_data, input_size, output);
     */
    virtual return_t hash (hash_context_t* handle, byte_t* source_data, size_t source_size, binary_t& output) = 0;
    /**
     * @brief free
     * @param void* data [in]
     * @return error code (see error.h)
     */
    virtual return_t free_data (void* data) = 0;

    /**
     * @brief type
     * @return see crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type () = 0;
};

}
}  // namespace

#endif
