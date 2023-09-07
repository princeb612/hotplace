/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPT__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPT__

#include <hotplace/sdk/crypto/crypto.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief openssl_crypt
 */
class openssl_crypt : public crypt_t
{
public:
    /**
     * @brief constructor
     */
    openssl_crypt ();
    /**
     * @brief destructor
     */
    virtual ~openssl_crypt ();

    /**
     * @brief create a context handle (symmetric)
     * @param crypt_context_t** handle [out]
     * @param crypt_algorithm_t algorithm [in]
     * @param crypt_mode_t mode [in]
     * @param const unsigned char* key [in]
     * @param unsigned size_key [in]
     * @param const unsigned char* iv [in] see openssl_chacha20_iv in case of crypt_algorithm_t::chacha20
     * @param unsigned size_iv [in]
     * @return error code (see error.hpp)
     * @example
     *        openssl_crypt crypt;
     *        crypt_context_t* handle = nullptr;
     *        crypt.open(&handle, crypt_algorithm_t::aes256, crypt_mode_t::cbc, key, size_key, iv, size_iv);
     *        crypt.close(handle);
     */
    virtual return_t open (crypt_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const unsigned char* key, unsigned size_key,
                           const unsigned char* iv, unsigned size_iv);
    /**
     * @brief destroy a context handle
     * @param crypt_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    virtual return_t close (crypt_context_t* handle);

    /**
     * @brief symmetric encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param unsigned char** data_encrypted [out]
     * @param size_t* size_encrypted [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, data_plain, size_plain, &data_encrypted, &size_encrypted);
     *        crypt.free_data(data_encrypted);
     */
    virtual return_t encrypt (crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, unsigned char** data_encrypted, size_t* size_encrypted);
    /**
     * @brief symmetric encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param binary_t& out_encrypted [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, data_plain, size_plain, data_encrypted);
     */
    virtual return_t encrypt (crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, binary_t& out_encrypted);

    /**
     * @brief encrypt (GCM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain
     * @param size_t size_plain [in]
     * @param binary_t& out_encrypte [out]
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [outopt]
     */
    virtual return_t encrypt2 (crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, binary_t& out_encrypted,
                               binary_t* aad = nullptr,
                               binary_t* tag = nullptr);
    /**
     * @brief encrypte
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param unsigned char* out_encrypted [out] allocated buffer
     * @param size_t* size* size_encrypted [inout] should be at least size_encrypted + EVP_MAX_BLOCK_LENGTH
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [inopt]
     */
    return_t encrypt2 (crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, unsigned char* out_encrypted, size_t* size_encrypted,
                       binary_t* aad = nullptr,
                       binary_t* tag = nullptr);
    /**
     * @brief symmetric decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param unsigned char** data_plain [out]
     * @param size_t* size_plain [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, data_encrypted, size_encrypted, &data_decrypted, &size_decrypted);
     *        crypt.free_data(data_decrypted);
     */
    virtual return_t decrypt (crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, unsigned char** data_plain, size_t* size_plain);
    /**
     * @brief symmetric decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param binary_t& out_decrypted [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, data_encrypted, size_encrypted, data_decrypted);
     */
    virtual return_t decrypt (crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, binary_t& out_decrypted);

    /**
     * @brief decrypt (GCM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param binary_t& out_decrypted [out]
     * @param binary_t* aad [inpot]
     * @param binary_t* tag [inopt]
     */
    virtual return_t decrypt2 (crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, binary_t& out_decrypted,
                               binary_t* aad = nullptr,
                               binary_t* tag = nullptr);
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param byte_t* out_decrypted [out] allocated buffer
     * @param size_t* size_decrypted [inout] should be at least size_encrypted + EVP_MAX_BLOCK_LENGTH
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [inopt]
     */
    return_t decrypt2 (crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, byte_t* out_decrypted, size_t* size_decrypted,
                       binary_t* aad = nullptr,
                       binary_t* tag = nullptr);
    /**
     * @brief free memory
     * @remarks see encrypt, decrypt
     */
    virtual return_t free_data (unsigned char* data);

    /**
     * @biref asymmetric encrypt
     * @param EVP_PKEY* pkey [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @param crypt_mode2_t mode [in]
     */
    return_t encrypt (EVP_PKEY* pkey, binary_t const& input, binary_t& output, crypt_mode2_t mode);
    /**
     * @biref asymmetric decrypt
     * @param EVP_PKEY* pkey [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @param crypt_mode2_t mode [in]
     */
    return_t decrypt (EVP_PKEY* pkey, binary_t const& input, binary_t& output, crypt_mode2_t mode);

    /**
     * @brief deprecated - expect block operation size
     * @param crypt_context_t* handle [in]
     * @param size_t size_data [in]
     * @param size_t* size_expect [out]
     * @return error code (see error.hpp)
     */
    //virtual return_t expect(crypt_context_t* handle, size_t size_data, size_t* size_expect);
    /**
     * @brief crypt_poweredby_t
     * @return see crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type ();

    /**
     * @brief query
     * @param crypt_context_t* handle [in]
     * @param size_t cmd [in] 1 key size, 2 iv size
     * @param size_t& value [out]
     */
    virtual return_t query (crypt_context_t* handle, size_t cmd, size_t& value);
};

}
}  // namespace

#endif
