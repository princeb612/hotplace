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


return_t kdf_hkdf (binary_t& derived, size_t dlen, binary_t const& key, binary_t const& salt, binary_t const& info, hash_algorithm_t alg);
return_t kdf_pbkdf2 (binary_t& derived, size_t dlen, std::string const& password, binary_t const& salt, int iter, hash_algorithm_t alg);
return_t kdf_scrypt (binary_t& derived, size_t dlen, std::string const& password, binary_t const& salt, int n, int r, int p);

// bcrypt - blowfish based... (openssl 3.x deprecates bf)

// openssl-3.2
// argon2d (data-depending memory access)
// argon2i (data-independing memory access)
// argon2id (mixed, hashing, derivation)

}
}  // namespace

#endif
