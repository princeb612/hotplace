/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   resource_jose_encryption.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <iostream>

namespace hotplace {
namespace crypto {

const hint_jose_encryption_t hint_jose_encryptions[] = {
    {
        "A128CBC-HS256",
        jose_hint_type_t::jwe,
        jwe_t::a128cbc_hs256,
        jwe_group_t::aescbc_hs,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::unknown,
        crypt_algorithm_t::aes128,
        crypt_mode_t::cbc,
        16,
        hash_algorithm_t::sha2_256,
    },
    {
        "A192CBC-HS384",
        jose_hint_type_t::jwe,
        jwe_t::a192cbc_hs384,
        jwe_group_t::aescbc_hs,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::unknown,
        crypt_algorithm_t::aes192,
        crypt_mode_t::cbc,
        24,
        hash_algorithm_t::sha2_384,
    },
    {
        "A256CBC-HS512",
        jose_hint_type_t::jwe,
        jwe_t::a256cbc_hs512,
        jwe_group_t::aescbc_hs,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::unknown,
        crypt_algorithm_t::aes256,
        crypt_mode_t::cbc,
        32,
        hash_algorithm_t::sha2_512,
    },
    {
        "A128GCM",
        jose_hint_type_t::jwe,
        jwe_t::a128gcm,
        jwe_group_t::aesgcm,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::unknown,
        crypt_algorithm_t::aes128,
        crypt_mode_t::gcm,
        16,
    },
    {
        "A192GCM",
        jose_hint_type_t::jwe,
        jwe_t::a192gcm,
        jwe_group_t::aesgcm,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::unknown,
        crypt_algorithm_t::aes192,
        crypt_mode_t::gcm,
        24,
    },
    {
        "A256GCM",
        jose_hint_type_t::jwe,
        jwe_t::a256gcm,
        jwe_group_t::aesgcm,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::unknown,
        crypt_algorithm_t::aes256,
        crypt_mode_t::gcm,
        32,
    },
};

const size_t sizeof_hint_jose_encryptions = RTL_NUMBER_OF(hint_jose_encryptions);

}  // namespace crypto
}  // namespace hotplace
