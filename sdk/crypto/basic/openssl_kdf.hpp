/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_KDF__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_KDF__

#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief   HKDF
 * @param   binary_t& derived [out] derived key
 * @param   size_t dlen [in]
 * @param   binary_t const& key [in]
 * @param   binary_t const& salt [in]
 * @param   binary_t const& info [in]
 * @param   hash_algorithm_t alg [in]
 */
return_t kdf_hkdf (binary_t& derived, size_t dlen, binary_t const& key, binary_t const& salt, binary_t const& info, hash_algorithm_t alg);
/**
 * @brief   PBKDF2
 * @param   binary_t& derived [out]
 * @param   size_t dlen [in]
 * @param   std::string const& password [in]
 * @param   binary_t const& salt [in]
 * @param   int iter [in]
 * @param   hash_algorithm_t alg [in]
 */
return_t kdf_pbkdf2 (binary_t& derived, size_t dlen, std::string const& password, binary_t const& salt, int iter, hash_algorithm_t alg);
/**
 * @brief   scrypt
 * @param   binary_t& derived [out]
 * @param   size_t dlen [in]
 * @param   std::string const& password [in]
 * @param   binary_t const& salt [in]
 * @param   int n [in]
 * @param   int r [in]
 * @param   int p [in]
 */
return_t kdf_scrypt (binary_t& derived, size_t dlen, std::string const& password, binary_t const& salt, int n, int r, int p);

// bcrypt - blowfish based... (openssl 3.x deprecates bf)

#if OPENSSL_VERSION_NUMBER >= 0x30200000L

// openssl-3.2
// argon2d (data-depending memory access)
// argon2i (data-independing memory access)
// argon2id (mixed, hashing, derivation)

enum argon2_t {
    argon2d = 1,
    argon2i = 2,
    argon2id= 3,
};
return_t kdf_argon2 (binary_t& derived, argon2_t mode, size_t dlen, binary_t const& password, binary_t const& salt, binary_t const& ad,  binary_t const& secret,
                     uint32 iteration_cost = 3,
                     uint32 parallel_cost = 4,
                     uint32 memory_cost = 32);
return_t kdf_argon2d (binary_t& derived, size_t dlen, binary_t const& password, binary_t const& salt,  binary_t const& ad, binary_t const& secret,
                      uint32 iteration_cost = 3,
                      uint32 parallel_cost = 4,
                      uint32 memory_cost = 32);
return_t kdf_argon2i (binary_t& derived, size_t dlen, binary_t const& password, binary_t const& salt,  binary_t const& ad, binary_t const& secret,
                      uint32 iteration_cost = 3,
                      uint32 parallel_cost = 4,
                      uint32 memory_cost = 32);
return_t kdf_argon2id (binary_t& derived, size_t dlen, binary_t const& password, binary_t const& salt,  binary_t const& ad, binary_t const& secret,
                       uint32 iteration_cost = 3,
                       uint32 parallel_cost = 4,
                       uint32 memory_cost = 32);

#endif

}
}  // namespace

#endif
