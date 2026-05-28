/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   resource_crypt.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

/* something wrong EVP_CIPHER_CTX_iv_length, EVP_CIPHER_CTX_block_size (openssl-1.1.1) */
const hint_blockcipher_t hint_blockciphers[] = {
    // 16 (128), 24 (192), 32 (256)

    {crypt_algorithm_t::aes128, 16, 16, 16, 16},
    {crypt_algorithm_t::aes192, 24, 16, 16, 24},
    {crypt_algorithm_t::aes256, 32, 16, 16, 32},
    {crypt_algorithm_t::blowfish, 16, 8, 8},
    {crypt_algorithm_t::aria128, 16, 16, 16},
    {crypt_algorithm_t::aria192, 24, 16, 16},
    {crypt_algorithm_t::aria256, 32, 16, 16},
    {crypt_algorithm_t::camellia128, 16, 16, 16},
    {crypt_algorithm_t::camellia192, 24, 16, 16},
    {crypt_algorithm_t::camellia256, 32, 16, 16},
    {crypt_algorithm_t::cast, 16, 8, 8},
    {crypt_algorithm_t::idea, 16, 8, 8},
    {crypt_algorithm_t::rc2, 8, 8, 8},
    {crypt_algorithm_t::rc5, 16, 8, 8},
    {crypt_algorithm_t::seed, 16, 16, 16},
    {crypt_algorithm_t::sm4, 16, 16, 16},
    {crypt_algorithm_t::rc4, 0, 12, 0},
    {crypt_algorithm_t::chacha20, 32, 12, 0},
};

const size_t sizeof_hint_blockciphers = RTL_NUMBER_OF(hint_blockciphers);

const hint_cipher_t evp_cipher_methods[] = {
    // scheme contains algorithm and mode, repetition just for convenience

    {crypto_scheme_t::aes_128_cbc, crypt_algorithm_t::aes128, crypt_mode_t::cbc, "aes-128-cbc"},
    {crypto_scheme_t::aes_128_ccm, crypt_algorithm_t::aes128, crypt_mode_t::ccm, "aes-128-ccm"},
    {crypto_scheme_t::aes_128_cfb, crypt_algorithm_t::aes128, crypt_mode_t::cfb, "aes-128-cfb"},
    {crypto_scheme_t::aes_128_cfb1, crypt_algorithm_t::aes128, crypt_mode_t::cfb1, "aes-128-cfb1"},
    {crypto_scheme_t::aes_128_cfb8, crypt_algorithm_t::aes128, crypt_mode_t::cfb8, "aes-128-cfb8"},
    {crypto_scheme_t::aes_128_ctr, crypt_algorithm_t::aes128, crypt_mode_t::ctr, "aes-128-ctr"},
    {crypto_scheme_t::aes_128_ecb, crypt_algorithm_t::aes128, crypt_mode_t::ecb, "aes-128-ecb"},
    {crypto_scheme_t::aes_128_gcm, crypt_algorithm_t::aes128, crypt_mode_t::gcm, "aes-128-gcm"},
    {crypto_scheme_t::aes_128_ofb, crypt_algorithm_t::aes128, crypt_mode_t::ofb, "aes-128-ofb"},

    {crypto_scheme_t::aes_192_cbc, crypt_algorithm_t::aes192, crypt_mode_t::cbc, "aes-192-cbc"},
    {crypto_scheme_t::aes_192_ccm, crypt_algorithm_t::aes192, crypt_mode_t::ccm, "aes-192-ccm"},
    {crypto_scheme_t::aes_192_cfb, crypt_algorithm_t::aes192, crypt_mode_t::cfb, "aes-192-cfb"},
    {crypto_scheme_t::aes_192_cfb1, crypt_algorithm_t::aes192, crypt_mode_t::cfb1, "aes-192-cfb1"},
    {crypto_scheme_t::aes_192_cfb8, crypt_algorithm_t::aes192, crypt_mode_t::cfb8, "aes-192-cfb8"},
    {crypto_scheme_t::aes_192_ctr, crypt_algorithm_t::aes192, crypt_mode_t::ctr, "aes-192-ctr"},
    {crypto_scheme_t::aes_192_ecb, crypt_algorithm_t::aes192, crypt_mode_t::ecb, "aes-192-ecb"},
    {crypto_scheme_t::aes_192_gcm, crypt_algorithm_t::aes192, crypt_mode_t::gcm, "aes-192-gcm"},
    {crypto_scheme_t::aes_192_ofb, crypt_algorithm_t::aes192, crypt_mode_t::ofb, "aes-192-ofb"},

    {crypto_scheme_t::aes_256_cbc, crypt_algorithm_t::aes256, crypt_mode_t::cbc, "aes-256-cbc"},
    {crypto_scheme_t::aes_256_ccm, crypt_algorithm_t::aes256, crypt_mode_t::ccm, "aes-256-ccm"},
    {crypto_scheme_t::aes_256_cfb, crypt_algorithm_t::aes256, crypt_mode_t::cfb, "aes-256-cfb"},
    {crypto_scheme_t::aes_256_cfb1, crypt_algorithm_t::aes256, crypt_mode_t::cfb1, "aes-256-cfb1"},
    {crypto_scheme_t::aes_256_cfb8, crypt_algorithm_t::aes256, crypt_mode_t::cfb8, "aes-256-cfb8"},
    {crypto_scheme_t::aes_256_ctr, crypt_algorithm_t::aes256, crypt_mode_t::ctr, "aes-256-ctr"},
    {crypto_scheme_t::aes_256_ecb, crypt_algorithm_t::aes256, crypt_mode_t::ecb, "aes-256-ecb"},
    {crypto_scheme_t::aes_256_gcm, crypt_algorithm_t::aes256, crypt_mode_t::gcm, "aes-256-gcm"},
    {crypto_scheme_t::aes_256_ofb, crypt_algorithm_t::aes256, crypt_mode_t::ofb, "aes-256-ofb"},

    {crypto_scheme_t::aria_128_cbc, crypt_algorithm_t::aria128, crypt_mode_t::cbc, "aria-128-cbc"},
    {crypto_scheme_t::aria_128_ccm, crypt_algorithm_t::aria128, crypt_mode_t::ccm, "aria-128-ccm"},
    {crypto_scheme_t::aria_128_cfb, crypt_algorithm_t::aria128, crypt_mode_t::cfb, "aria-128-cfb"},
    {crypto_scheme_t::aria_128_cfb1, crypt_algorithm_t::aria128, crypt_mode_t::cfb1, "aria-128-cfb1"},
    {crypto_scheme_t::aria_128_cfb8, crypt_algorithm_t::aria128, crypt_mode_t::cfb8, "aria-128-cfb8"},
    {crypto_scheme_t::aria_128_ctr, crypt_algorithm_t::aria128, crypt_mode_t::ctr, "aria-128-ctr"},
    {crypto_scheme_t::aria_128_ecb, crypt_algorithm_t::aria128, crypt_mode_t::ecb, "aria-128-ecb"},
    {crypto_scheme_t::aria_128_gcm, crypt_algorithm_t::aria128, crypt_mode_t::gcm, "aria-128-gcm"},
    {crypto_scheme_t::aria_128_ofb, crypt_algorithm_t::aria128, crypt_mode_t::ofb, "aria-128-ofb"},

    {crypto_scheme_t::aria_192_cbc, crypt_algorithm_t::aria192, crypt_mode_t::cbc, "aria-192-cbc"},
    {crypto_scheme_t::aria_192_ccm, crypt_algorithm_t::aria192, crypt_mode_t::ccm, "aria-192-ccm"},
    {crypto_scheme_t::aria_192_cfb, crypt_algorithm_t::aria192, crypt_mode_t::cfb, "aria-192-cfb"},
    {crypto_scheme_t::aria_192_cfb1, crypt_algorithm_t::aria192, crypt_mode_t::cfb1, "aria-192-cfb1"},
    {crypto_scheme_t::aria_192_cfb8, crypt_algorithm_t::aria192, crypt_mode_t::cfb8, "aria-192-cfb8"},
    {crypto_scheme_t::aria_192_ctr, crypt_algorithm_t::aria192, crypt_mode_t::ctr, "aria-192-ctr"},
    {crypto_scheme_t::aria_192_ecb, crypt_algorithm_t::aria192, crypt_mode_t::ecb, "aria-192-ecb"},
    {crypto_scheme_t::aria_192_gcm, crypt_algorithm_t::aria192, crypt_mode_t::gcm, "aria-192-gcm"},
    {crypto_scheme_t::aria_192_ofb, crypt_algorithm_t::aria192, crypt_mode_t::ofb, "aria-192-ofb"},

    {crypto_scheme_t::aria_256_cbc, crypt_algorithm_t::aria256, crypt_mode_t::cbc, "aria-256-cbc"},
    {crypto_scheme_t::aria_256_ccm, crypt_algorithm_t::aria256, crypt_mode_t::ccm, "aria-256-ccm"},
    {crypto_scheme_t::aria_256_cfb, crypt_algorithm_t::aria256, crypt_mode_t::cfb, "aria-256-cfb"},
    {crypto_scheme_t::aria_256_cfb1, crypt_algorithm_t::aria256, crypt_mode_t::cfb1, "aria-256-cfb1"},
    {crypto_scheme_t::aria_256_cfb8, crypt_algorithm_t::aria256, crypt_mode_t::cfb8, "aria-256-cfb8"},
    {crypto_scheme_t::aria_256_ctr, crypt_algorithm_t::aria256, crypt_mode_t::ctr, "aria-256-ctr"},
    {crypto_scheme_t::aria_256_ecb, crypt_algorithm_t::aria256, crypt_mode_t::ecb, "aria-256-ecb"},
    {crypto_scheme_t::aria_256_gcm, crypt_algorithm_t::aria256, crypt_mode_t::gcm, "aria-256-gcm"},
    {crypto_scheme_t::aria_256_ofb, crypt_algorithm_t::aria256, crypt_mode_t::ofb, "aria-256-ofb"},

    {crypto_scheme_t::bf_cbc, crypt_algorithm_t::blowfish, crypt_mode_t::cbc, "bf-cbc"},
    {crypto_scheme_t::bf_cfb, crypt_algorithm_t::blowfish, crypt_mode_t::cfb, "bf-cfb"},
    {crypto_scheme_t::bf_ecb, crypt_algorithm_t::blowfish, crypt_mode_t::ecb, "bf-ecb"},
    {crypto_scheme_t::bf_ofb, crypt_algorithm_t::blowfish, crypt_mode_t::ofb, "bf-ofb"},

    // RFC 6367 mentions Camellia GCM

    {crypto_scheme_t::camellia_128_cbc, crypt_algorithm_t::camellia128, crypt_mode_t::cbc, "camellia-128-cbc"},
    {crypto_scheme_t::camellia_128_cfb, crypt_algorithm_t::camellia128, crypt_mode_t::cfb, "camellia-128-cfb"},
    {crypto_scheme_t::camellia_128_cfb1, crypt_algorithm_t::camellia128, crypt_mode_t::cfb1, "camellia-128-cfb1"},
    {crypto_scheme_t::camellia_128_cfb8, crypt_algorithm_t::camellia128, crypt_mode_t::cfb8, "camellia-128-cfb8"},
    {crypto_scheme_t::camellia_128_ctr, crypt_algorithm_t::camellia128, crypt_mode_t::ctr, "camellia-128-ctr"},
    {crypto_scheme_t::camellia_128_ecb, crypt_algorithm_t::camellia128, crypt_mode_t::ecb, "camellia-128-ecb"},
    {crypto_scheme_t::camellia_128_gcm, crypt_algorithm_t::camellia128, crypt_mode_t::gcm, "camellia-128-gcm"},
    {crypto_scheme_t::camellia_128_ofb, crypt_algorithm_t::camellia128, crypt_mode_t::ofb, "camellia-128-ofb"},

    {crypto_scheme_t::camellia_192_cbc, crypt_algorithm_t::camellia192, crypt_mode_t::cbc, "camellia-192-cbc"},
    {crypto_scheme_t::camellia_192_cfb, crypt_algorithm_t::camellia192, crypt_mode_t::cfb, "camellia-192-cfb"},
    {crypto_scheme_t::camellia_192_cfb1, crypt_algorithm_t::camellia192, crypt_mode_t::cfb1, "camellia-192-cfb1"},
    {crypto_scheme_t::camellia_192_cfb8, crypt_algorithm_t::camellia192, crypt_mode_t::cfb8, "camellia-192-cfb8"},
    {crypto_scheme_t::camellia_192_ctr, crypt_algorithm_t::camellia192, crypt_mode_t::ctr, "camellia-192-ctr"},
    {crypto_scheme_t::camellia_192_ecb, crypt_algorithm_t::camellia192, crypt_mode_t::ecb, "camellia-192-ecb"},
    {crypto_scheme_t::camellia_192_gcm, crypt_algorithm_t::camellia192, crypt_mode_t::gcm, "camellia-192-gcm"},
    {crypto_scheme_t::camellia_192_ofb, crypt_algorithm_t::camellia192, crypt_mode_t::ofb, "camellia-192-ofb"},

    {crypto_scheme_t::camellia_256_cbc, crypt_algorithm_t::camellia256, crypt_mode_t::cbc, "camellia-256-cbc"},
    {crypto_scheme_t::camellia_256_cfb, crypt_algorithm_t::camellia256, crypt_mode_t::cfb, "camellia-256-cfb"},
    {crypto_scheme_t::camellia_256_cfb1, crypt_algorithm_t::camellia256, crypt_mode_t::cfb1, "camellia-256-cfb1"},
    {crypto_scheme_t::camellia_256_cfb8, crypt_algorithm_t::camellia256, crypt_mode_t::cfb8, "camellia-256-cfb8"},
    {crypto_scheme_t::camellia_256_ctr, crypt_algorithm_t::camellia256, crypt_mode_t::ctr, "camellia-256-ctr"},
    {crypto_scheme_t::camellia_256_ecb, crypt_algorithm_t::camellia256, crypt_mode_t::ecb, "camellia-256-ecb"},
    {crypto_scheme_t::camellia_256_gcm, crypt_algorithm_t::camellia256, crypt_mode_t::gcm, "camellia-256-gcm"},
    {crypto_scheme_t::camellia_256_ofb, crypt_algorithm_t::camellia256, crypt_mode_t::ofb, "camellia-256-ofb"},

    {crypto_scheme_t::cast5_cbc, crypt_algorithm_t::cast, crypt_mode_t::cbc, "cast5-cbc"},
    {crypto_scheme_t::cast5_cfb, crypt_algorithm_t::cast, crypt_mode_t::cfb, "cast5-cfb"},
    {crypto_scheme_t::cast5_ecb, crypt_algorithm_t::cast, crypt_mode_t::ecb, "cast5-ecb"},
    {crypto_scheme_t::cast5_ofb, crypt_algorithm_t::cast, crypt_mode_t::ofb, "cast5-ofb"},

    {crypto_scheme_t::idea_cbc, crypt_algorithm_t::idea, crypt_mode_t::cbc, "idea-cbc"},
    {crypto_scheme_t::idea_cfb, crypt_algorithm_t::idea, crypt_mode_t::cfb, "idea-cfb"},
    {crypto_scheme_t::idea_ecb, crypt_algorithm_t::idea, crypt_mode_t::ecb, "idea-ecb"},
    {crypto_scheme_t::idea_ofb, crypt_algorithm_t::idea, crypt_mode_t::ofb, "idea-ofb"},

    {crypto_scheme_t::rc2_cbc, crypt_algorithm_t::rc2, crypt_mode_t::cbc, "rc2-cbc"},
    {crypto_scheme_t::rc2_cfb, crypt_algorithm_t::rc2, crypt_mode_t::cfb, "rc2-cfb"},
    {crypto_scheme_t::rc2_ecb, crypt_algorithm_t::rc2, crypt_mode_t::ecb, "rc2-ecb"},
    {crypto_scheme_t::rc2_ofb, crypt_algorithm_t::rc2, crypt_mode_t::ofb, "rc2-ofb"},

    {crypto_scheme_t::rc5_cbc, crypt_algorithm_t::rc5, crypt_mode_t::cbc, "rc5-cbc"},
    {crypto_scheme_t::rc5_cfb, crypt_algorithm_t::rc5, crypt_mode_t::cfb, "rc5-cfb"},
    {crypto_scheme_t::rc5_ecb, crypt_algorithm_t::rc5, crypt_mode_t::ecb, "rc5-ecb"},
    {crypto_scheme_t::rc5_ofb, crypt_algorithm_t::rc5, crypt_mode_t::ofb, "rc5-ofb"},

    {crypto_scheme_t::sm4_cbc, crypt_algorithm_t::sm4, crypt_mode_t::cbc, "sm4-cbc"},
    {crypto_scheme_t::sm4_cfb, crypt_algorithm_t::sm4, crypt_mode_t::cfb, "sm4-cfb"},
    {crypto_scheme_t::sm4_ecb, crypt_algorithm_t::sm4, crypt_mode_t::ecb, "sm4-ecb"},
    {crypto_scheme_t::sm4_ofb, crypt_algorithm_t::sm4, crypt_mode_t::ofb, "sm4-ofb"},
    {crypto_scheme_t::sm4_ctr, crypt_algorithm_t::sm4, crypt_mode_t::ctr, "sm4-ctr"},

    {crypto_scheme_t::seed_cbc, crypt_algorithm_t::seed, crypt_mode_t::cbc, "seed-cbc"},
    {crypto_scheme_t::seed_cfb, crypt_algorithm_t::seed, crypt_mode_t::cfb, "seed-cfb"},
    {crypto_scheme_t::seed_ecb, crypt_algorithm_t::seed, crypt_mode_t::ecb, "seed-ecb"},
    {crypto_scheme_t::seed_ofb, crypt_algorithm_t::seed, crypt_mode_t::ofb, "seed-ofb"},

    {crypto_scheme_t::rc4, crypt_algorithm_t::rc4, crypt_mode_t::unknown, "rc4"},
    {crypto_scheme_t::chacha20, crypt_algorithm_t::chacha20, crypt_mode_t::unknown, "chacha20"},
    {crypto_scheme_t::chacha20_poly1305, crypt_algorithm_t::chacha20, crypt_mode_t::poly1305, "chacha20-poly1305"},

    // SET_L 3, SET_IVLEN=15-L=12, AEAD_SET_TAG 16 or 8
    {crypto_scheme_t::tls_aes_128_gcm, crypt_algorithm_t::aes128, crypt_mode_t::gcm, "aes-128-gcm", 15 - 3, 16},
    {crypto_scheme_t::tls_aes_256_gcm, crypt_algorithm_t::aes256, crypt_mode_t::gcm, "aes-256-gcm", 15 - 3, 16},
    {crypto_scheme_t::tls_aes_128_ccm, crypt_algorithm_t::aes128, crypt_mode_t::ccm, "aes-128-ccm", 15 - 3, 16},
    {crypto_scheme_t::tls_aes_256_ccm, crypt_algorithm_t::aes256, crypt_mode_t::ccm, "aes-256-ccm", 15 - 3, 16},
    {crypto_scheme_t::tls_aes_128_ccm_8, crypt_algorithm_t::aes128, crypt_mode_t::ccm, "aes-128-ccm", 15 - 3, 8},
    {crypto_scheme_t::tls_aes_256_ccm_8, crypt_algorithm_t::aes256, crypt_mode_t::ccm, "aes-256-ccm", 15 - 3, 8},
    {crypto_scheme_t::tls_chacha20_poly1305, crypt_algorithm_t::chacha20, crypt_mode_t::poly1305, "chacha20-poly1305", 15 - 3, 16},
    {crypto_scheme_t::tls_aria_128_gcm, crypt_algorithm_t::aria128, crypt_mode_t::gcm, "aria-128-gcm", 15 - 3, 16},
    {crypto_scheme_t::tls_aria_256_gcm, crypt_algorithm_t::aria256, crypt_mode_t::gcm, "aria-256-gcm", 15 - 3, 16},
    {crypto_scheme_t::tls_aria_128_ccm, crypt_algorithm_t::aria128, crypt_mode_t::ccm, "aria-128-ccm", 15 - 3, 16},
    {crypto_scheme_t::tls_aria_256_ccm, crypt_algorithm_t::aria256, crypt_mode_t::ccm, "aria-256-ccm", 15 - 3, 16},
    {crypto_scheme_t::tls_camellia_128_gcm, crypt_algorithm_t::camellia128, crypt_mode_t::gcm, "camellia-128-gcm", 15 - 3, 16},
    {crypto_scheme_t::tls_camellia_256_gcm, crypt_algorithm_t::camellia256, crypt_mode_t::gcm, "camellia-256-gcm", 15 - 3, 16},

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    {crypto_scheme_t::aes_128_wrap, crypt_algorithm_t::aes128, crypt_mode_t::wrap, "aes-128-wrap"},
    {crypto_scheme_t::aes_192_wrap, crypt_algorithm_t::aes192, crypt_mode_t::wrap, "aes-192-wrap"},
    {crypto_scheme_t::aes_256_wrap, crypt_algorithm_t::aes256, crypt_mode_t::wrap, "aes-256-wrap"},
#endif
};

const size_t sizeof_evp_cipher_methods = RTL_NUMBER_OF(evp_cipher_methods);

const evp_cipher_ossl1_methods ossl1_aes_wrap_methods[] = {
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    {EVP_aes_128_wrap(), {crypto_scheme_t::aes_128_wrap, crypt_algorithm_t::aes128, crypt_mode_t::wrap, "aes-128-wrap"}},
    {EVP_aes_192_wrap(), {crypto_scheme_t::aes_192_wrap, crypt_algorithm_t::aes192, crypt_mode_t::wrap, "aes-192-wrap"}},
    {EVP_aes_256_wrap(), {crypto_scheme_t::aes_256_wrap, crypt_algorithm_t::aes256, crypt_mode_t::wrap, "aes-256-wrap"}},
#else
#ifdef _MSC_VER
    {},  // C2466
#endif
#endif
};

const size_t sizeof_ossl1_aes_wrap_methods = RTL_NUMBER_OF(ossl1_aes_wrap_methods);

}  // namespace crypto
}  // namespace hotplace
