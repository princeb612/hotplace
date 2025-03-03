/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <iostream>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/io/system/sdk.hpp>

namespace hotplace {
namespace crypto {

const hint_jose_encryption_t hint_jose_algorithms[] = {
    {
        "RSA1_5",
        jwa_t::jwa_rsa_1_5,
        jwa_group_t::jwa_group_rsa,
        crypto_kty_t::kty_rsa,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::rsa_1_5,
    },
    {
        "RSA-OAEP",
        jwa_t::jwa_rsa_oaep,
        jwa_group_t::jwa_group_rsa,
        crypto_kty_t::kty_rsa,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::rsa_oaep,
    },
    {
        "RSA-OAEP-256",
        jwa_t::jwa_rsa_oaep_256,
        jwa_group_t::jwa_group_rsa,
        crypto_kty_t::kty_rsa,
        crypto_kty_t::kty_unknown,
        crypt_enc_t::rsa_oaep256,
    },
    {
        "A128KW",
        jwa_t::jwa_a128kw,
        jwa_group_t::jwa_group_aeskw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes128,
        crypt_mode_t::wrap,
        16,
        hash_algorithm_t::sha2_256,
    },
    {
        "A192KW",
        jwa_t::jwa_a192kw,
        jwa_group_t::jwa_group_aeskw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes192,
        crypt_mode_t::wrap,
        24,
        hash_algorithm_t::sha2_384,
    },
    {
        "A256KW",
        jwa_t::jwa_a256kw,
        jwa_group_t::jwa_group_aeskw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::wrap,
        32,
        hash_algorithm_t::sha2_512,
    },
    {
        "dir",
        jwa_t::jwa_dir,
        jwa_group_t::jwa_group_dir,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
    },
    {
        "ECDH-ES",
        jwa_t::jwa_ecdh_es,
        jwa_group_t::jwa_group_ecdh,
        crypto_kty_t::kty_ec,
        crypto_kty_t::kty_okp,
    },
    {
        "ECDH-ES+A128KW",
        jwa_t::jwa_ecdh_es_a128kw,
        jwa_group_t::jwa_group_ecdh_aeskw,
        crypto_kty_t::kty_ec,
        crypto_kty_t::kty_okp,
        0,
        crypt_algorithm_t::aes128,
        crypt_mode_t::wrap,
        16,
    },
    {
        "ECDH-ES+A192KW",
        jwa_t::jwa_ecdh_es_a192kw,
        jwa_group_t::jwa_group_ecdh_aeskw,
        crypto_kty_t::kty_ec,
        crypto_kty_t::kty_okp,
        0,
        crypt_algorithm_t::aes192,
        crypt_mode_t::wrap,
        24,
    },
    {
        "ECDH-ES+A256KW",
        jwa_t::jwa_ecdh_es_a256kw,
        jwa_group_t::jwa_group_ecdh_aeskw,
        crypto_kty_t::kty_ec,
        crypto_kty_t::kty_okp,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::wrap,
        32,
    },
    {
        "A128GCMKW",
        jwa_t::jwa_a128gcmkw,
        jwa_group_t::jwa_group_aesgcmkw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes128,
        crypt_mode_t::gcm,
        16,
    },
    {
        "A192GCMKW",
        jwa_t::jwa_a192gcmkw,
        jwa_group_t::jwa_group_aesgcmkw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes192,
        crypt_mode_t::gcm,
        24,
    },
    {
        "A256GCMKW",
        jwa_t::jwa_a256gcmkw,
        jwa_group_t::jwa_group_aesgcmkw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::gcm,
        32,
    },
    {
        "PBES2-HS256+A128KW",
        jwa_t::jwa_pbes2_hs256_a128kw,
        jwa_group_t::jwa_group_pbes_hs_aeskw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes128,
        crypt_mode_t::wrap,
        16,
        hash_algorithm_t::sha2_256,
    },
    {
        "PBES2-HS384+A192KW",
        jwa_t::jwa_pbes2_hs384_a192kw,
        jwa_group_t::jwa_group_pbes_hs_aeskw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes192,
        crypt_mode_t::wrap,
        24,
        hash_algorithm_t::sha2_384,
    },
    {
        "PBES2-HS512+A256KW",
        jwa_t::jwa_pbes2_hs512_a256kw,
        jwa_group_t::jwa_group_pbes_hs_aeskw,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::wrap,
        32,
        hash_algorithm_t::sha2_512,
    },
};

const hint_jose_encryption_t hint_jose_encryptions[] = {
    {
        "A128CBC-HS256",
        jwe_t::jwe_a128cbc_hs256,
        jwe_group_t::jwe_group_aescbc_hs,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes128,
        crypt_mode_t::cbc,
        16,
        hash_algorithm_t::sha2_256,
    },
    {
        "A192CBC-HS384",
        jwe_t::jwe_a192cbc_hs384,
        jwe_group_t::jwe_group_aescbc_hs,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes192,
        crypt_mode_t::cbc,
        24,
        hash_algorithm_t::sha2_384,
    },
    {
        "A256CBC-HS512",
        jwe_t::jwe_a256cbc_hs512,
        jwe_group_t::jwe_group_aescbc_hs,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::cbc,
        32,
        hash_algorithm_t::sha2_512,
    },
    {
        "A128GCM",
        jwe_t::jwe_a128gcm,
        jwe_group_t::jwe_group_aesgcm,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes128,
        crypt_mode_t::gcm,
        16,
    },
    {
        "A192GCM",
        jwe_t::jwe_a192gcm,
        jwe_group_t::jwe_group_aesgcm,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes192,
        crypt_mode_t::gcm,
        24,
    },
    {
        "A256GCM",
        jwe_t::jwe_a256gcm,
        jwe_group_t::jwe_group_aesgcm,
        crypto_kty_t::kty_oct,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::gcm,
        32,
    },
};

const size_t sizeof_hint_jose_algorithms = RTL_NUMBER_OF(hint_jose_algorithms);
const size_t sizeof_hint_jose_encryptions = RTL_NUMBER_OF(hint_jose_encryptions);

const char* nameof_alg(const hint_jose_encryption_t* hint) {
    const char* ret_value = nullptr;
    if (hint) {
        ret_value = hint->alg_name;
    }
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
