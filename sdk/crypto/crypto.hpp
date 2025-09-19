/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPTO__
#define __HOTPLACE_SDK_CRYPTO_CRYPTO__

#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

enum crypt_ctrl_t {
    crypt_ctrl_padding = 1,  // EVP_CIPHER_CTX_set_padding
    crypt_ctrl_nsize = 2,    // SET_IVLEN=15-L
    crypt_ctrl_tsize = 3,    // AEAD_SET_TAG
};

class crypt_t {
   public:
    /**
     * @brief create a context handle
     * @param crypt_context_t** handle [out]
     * @param crypt_algorithm_t algorithm [in]
     * @param crypt_mode_t mode [in]
     * @param const unsigned char* key [in]
     * @param unsigned size_key [in]
     * @param const unsigned char* iv [in]
     * @param unsigned size_iv [in]
     * @return error code (see error.hpp)
     * @example
     *        crypt_context_t* handle = nullptr;
     *        crypt.open(&handle, crypt_algorithm_t::aes256, crypt_mode_t::cbc, key, size_key, iv, size_iv);
     *        crypt.close(handle);
     */
    virtual return_t open(crypt_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const unsigned char* key, unsigned size_key,
                          const unsigned char* iv, unsigned size_iv) = 0;
    /**
     * @brief create a context handle (symmetric)
     * @param crypt_context_t** handle [out]
     * @param crypt_algorithm_t algorithm [in]
     * @param crypt_mode_t mode [in]
     * @param const binary_t& key [in]
     * @param const binary_t& iv [in]
     * @return error code (see error.hpp)
     */
    virtual return_t open(crypt_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv) = 0;
    /**
     * @brief create a context handle (symmetric)
     * @param crypt_context_t** handle [out]
     * @param const char* cipher [in] ex. "aes-128-cbc"
     * @param const binary_t& key [in]
     * @param const binary_t& iv [in]
     * @return error code (see error.hpp)
     */
    virtual return_t open(crypt_context_t** handle, const char* cipher, const unsigned char* key, size_t size_key, const unsigned char* iv, size_t size_iv) = 0;
    virtual return_t open(crypt_context_t** handle, const char* cipher, const binary_t& key, const binary_t& iv) = 0;
    /**
     * @brief destroy a context handle
     * @param crypt_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    virtual return_t close(crypt_context_t* handle) = 0;
    /**
     * @brief set
     * @param crypt_context_t* handle [in]
     * @param crypt_ctrl_t id [in]
     * @param uint16 param [in]
     */
    virtual return_t set(crypt_context_t* handle, crypt_ctrl_t id, uint16 param) = 0;
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* plaintext [in]
     * @param size_t plainsize [in]
     * @param unsigned char** ciphertext [out] call free_data to free
     * @param size_t* ciphersize [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, plaintext, plainsize, &ciphertext, &ciphersize);
     *        crypt.free_data(ciphertext);
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, unsigned char** ciphertext, size_t* ciphersize) = 0;
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* plaintext [in]
     * @param size_t plainsize [in]
     * @param binary_t& ciphertext [out]
     * @return error code (see error.hpp)
     * @example
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, binary_t& ciphertext) = 0;
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const binary_t& plaintext [in]
     * @param binary_t& ciphertext [out]
     * @return error code (see error.hpp)
     * @example
     */
    virtual return_t encrypt(crypt_context_t* handle, const binary_t& plaintext, binary_t& ciphertext) = 0;

    /**
     * @brief encrypt (GCM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* plaintext
     * @param size_t plainsize [in]
     * @param binary_t& ciphertext [out]
     * @param const binary_t& aad [in]
     * @param binary_t& tag [out]
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, binary_t& ciphertext, const binary_t& aad,
                             binary_t& tag) = 0;
    /**
     * @brief encrypt (GCM/CCM)
     * @param crypt_context_t* handle [in]
     * @param const binary_t& plaintext [in]
     * @param binary_t& ciphertext [out]
     * @param const binary_t& aad [in]
     * @param binary_t& tag [out]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt(crypt_context_t* handle, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag) = 0;

    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* ciphertext [in]
     * @param size_t ciphersize [in]
     * @param unsigned char** plaintext [out]
     * @param size_t* plainsize [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, ciphertext, ciphersize, &data_decrypted, &size_decrypted);
     *        crypt.free_data(data_decrypted);
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, unsigned char** plaintext, size_t* plainsize) = 0;
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* ciphertext [in]
     * @param size_t ciphersize [in]
     * @param binary_t& plaintext [out]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, binary_t& plaintext) = 0;
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const binary_t& ciphertext [in]
     * @param binary_t& plaintext [out]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const binary_t& ciphertext, binary_t& plaintext) = 0;

    /**
     * @brief decrypt (GCM/CCOM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* ciphertext [in]
     * @param size_t ciphersize [in]
     * @param binary_t& plaintext [out]
     * @param const binary_t& aad [in]
     * @param const binary_t& tag [in]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag) = 0;
    /**
     * @brief decrypt (GCM/CCOM)
     * @param crypt_context_t* handle [in]
     * @param const binary_t& ciphertext [in]
     * @param binary_t& plaintext [out]
     * @param const binary_t& aad [in]
     * @param const binary_t& tag [in]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad, const binary_t& tag) = 0;

    /**
     * @brief free
     * @param unsigned char* data [in]
     * @return error code (see error.hpp)
     */
    virtual return_t free_data(unsigned char* data) = 0;

    /**
     * @brief crypt_poweredby_t
     * @return see crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type() = 0;
    /**
     * @brief query
     * @param crypt_context_t* handle [in]
     * @param size_t cmd [in] 1 key size, 2 iv size
     * @param size_t& value [out]
     * @return error code (see error.hpp)
     */
    virtual return_t query(crypt_context_t* handle, size_t cmd, size_t& value) = 0;

   protected:
};

class hash_t {
   public:
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
     *    hash.open(&handle, "sha256"); // wo key
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
    virtual return_t open(hash_context_t** handle, const char* algorithm, const unsigned char* key = nullptr, unsigned keysize = 0) = 0;
    /**
     * @brief open (HMAC, CMAC)
     */
    virtual return_t open(hash_context_t** handle, const char* algorithm, const binary_t& key) = 0;

    virtual return_t open(hash_context_t** handle, hash_algorithm_t alg, const unsigned char* key = nullptr, unsigned keysize = 0) = 0;
    /**
     * @brief open (HMAC)
     */
    virtual return_t open(hash_context_t** handle, hash_algorithm_t alg, const binary_t& key) = 0;
    /**
     * @brief open (CMAC)
     * @param hash_context_t** handle [out]
     * @param crypt_algorithm_t alg [in]
     * @param crypt_mode_t mode [in]
     * @param const unsigned char* key [in]
     * @param unsigned keysize [in]
     * @return error code (see error.hpp)
     */
    virtual return_t open(hash_context_t** handle, crypt_algorithm_t alg, crypt_mode_t mode, const unsigned char* key, unsigned keysize) = 0;
    /**
     * @brief open (CMAC)
     */
    virtual return_t open(hash_context_t** handle, crypt_algorithm_t alg, crypt_mode_t mode, const binary_t& key) = 0;
    /**
     * @brief close
     * @param hash_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    virtual return_t close(hash_context_t* handle) = 0;
    /**
     * @brief initialize a new digest operation
     * @param hash_context_t* handle [in]
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t init(hash_context_t* handle) = 0;
    /**
     * @brief update
     * @param hash_context_t* handle [in]
     * @param const byte_t* data [out]
     * @param size_t datasize [in]
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t update(hash_context_t* handle, const byte_t* data, size_t datasize) = 0;
    virtual return_t update(hash_context_t* handle, const binary_t& input) = 0;

    /**
     * @brief   update and get hash
     * @sample
     *          hash.open(&handle, "sha256");
     *          hash.init(handle);
     *          hash.update(handle, (byte_t*)stream1, strlen(stream1), hash_stream1);
     *          _logger->hdump("stream1", hash_stream1);
     *          hash.update(handle, (byte_t*)stream2, strlen(stream2), hash_stream2);
     *          _logger->hdump("stream1", hash_stream2);
     *          hash.close(handle);
     */
    virtual return_t update(hash_context_t* handle, const byte_t* data, size_t datasize, binary_t& digest) = 0;
    virtual return_t update(hash_context_t* handle, const binary_t& input, binary_t& digest) = 0;

    /**
     * @brief get
     * @param hash_context_t* handle [in]
     * @param byte_t** data [out]
     * @param size_t * datasize [out] call free_data to free
     * @return error code (see error.hpp)
     * @example
     *        hash.init(handle);
     *        hash.update(handle, input_data, input_size);
     *        hash.finalize(handle, &output_data, &output_size);
     *        hash.free_data(output_data);
     */
    virtual return_t finalize(hash_context_t* handle, byte_t** data, size_t* datasize) = 0;
    /**
     * @brief finalize
     * @param hash_context_t* handle [in]
     * @param binary_t& hash [out]
     */
    virtual return_t finalize(hash_context_t* handle, binary_t& hash) = 0;
    /**
     * @brief get
     * @param hash_context_t* handle [in]
     * @param const byte_t* source_data [in]
     * @param size_t source_size [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @example
     *        hash.hash(handle, input_data, input_size, output);
     */
    virtual return_t hash(hash_context_t* handle, const byte_t* source_data, size_t source_size, binary_t& output) = 0;
    /**
     * @brief free
     * @param void* data [in]
     * @return error code (see error.hpp)
     */
    virtual return_t free_data(void* data) = 0;

    /**
     * @brief type
     * @return see crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type() = 0;
};

}  // namespace crypto
}  // namespace hotplace

#endif
