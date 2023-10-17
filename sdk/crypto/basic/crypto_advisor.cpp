/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>

namespace hotplace {
namespace crypto {

#define CRYPT_CIPHER_VALUE(a, m) ((a << 16) | m)

#ifndef OPENSSL_NO_IDEA
#define EVP_CIPHER_IDEA_CBC EVP_idea_cbc()
#define EVP_CIPHER_IDEA_CFB EVP_idea_cfb()
#define EVP_CIPHER_IDEA_ECB EVP_idea_ecb()
#define EVP_CIPHER_IDEA_OFB EVP_idea_ofb()
#else
#define EVP_CIPHER_IDEA_CBC nullptr
#define EVP_CIPHER_IDEA_CFB nullptr
#define EVP_CIPHER_IDEA_ECB nullptr
#define EVP_CIPHER_IDEA_OFB nullptr
#endif
#ifndef OPENSSL_NO_RC2
#define EVP_CIPHER_RC2_CBC EVP_rc2_cbc()
#define EVP_CIPHER_RC2_CFB EVP_rc2_cfb()
#define EVP_CIPHER_RC2_ECB EVP_rc2_ecb()
#define EVP_CIPHER_RC2_OFB EVP_rc2_ofb()
#else
#define EVP_CIPHER_RC2_CBC nullptr
#define EVP_CIPHER_RC2_CFB nullptr
#define EVP_CIPHER_RC2_ECB nullptr
#define EVP_CIPHER_RC2_OFB nullptr
#endif
#ifndef OPENSSL_NO_RC5
#define EVP_CIPHER_RC5_CBC EVP_rc5_32_12_16_cbc()
#define EVP_CIPHER_RC5_CFB EVP_rc5_32_12_16_cfb()
#define EVP_CIPHER_RC5_ECB EVP_rc5_32_12_16_ecb()
#define EVP_CIPHER_RC5_OFB EVP_rc5_32_12_16_ofb()
#else
#define EVP_CIPHER_RC5_CBC nullptr
#define EVP_CIPHER_RC5_CFB nullptr
#define EVP_CIPHER_RC5_ECB nullptr
#define EVP_CIPHER_RC5_OFB nullptr
#endif
#ifndef OPENSSL_NO_SM4
#define EVP_CIPHER_SM4_CBC EVP_sm4_cbc()
#define EVP_CIPHER_SM4_CFB EVP_sm4_cfb()
#define EVP_CIPHER_SM4_ECB EVP_sm4_ecb()
#define EVP_CIPHER_SM4_OFB EVP_sm4_ofb()
#define EVP_CIPHER_SM4_CTR EVP_sm4_ctr()
#else
#define EVP_CIPHER_SM4_CBC nullptr
#define EVP_CIPHER_SM4_CFB nullptr
#define EVP_CIPHER_SM4_ECB nullptr
#define EVP_CIPHER_SM4_OFB nullptr
#define EVP_CIPHER_SM4_CTR nullptr
#endif

const openssl_evp_cipher_method_t evp_cipher_methods[] = {
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::cbc,
        EVP_aes_128_cbc(),
        "aes-128-cbc",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::ccm,
        EVP_aes_128_ccm(),
        "aes-128-ccm",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::cfb,
        EVP_aes_128_cfb(),
        "aes-128-cfb",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::cfb1,
        EVP_aes_128_cfb1(),
        "aes-128-cfb1",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::cfb8,
        EVP_aes_128_cfb8(),
        "aes-128-cfb8",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::ctr,
        EVP_aes_128_ctr(),
        "aes-128-ctr",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::ecb,
        EVP_aes_128_ecb(),
        "aes-128-ecb",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::gcm,
        EVP_aes_128_gcm(),
        "aes-128-gcm",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::ofb,
        EVP_aes_128_ofb(),
        "aes-128-ofb",
    },
    {
        crypt_algorithm_t::aes128,
        crypt_mode_t::wrap,
        EVP_aes_128_wrap(),
        "aes-128-wrap",
    },

    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::cbc,
        EVP_aes_192_cbc(),
        "aes-192-cbc",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::ccm,
        EVP_aes_192_ccm(),
        "aes-192-ccm",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::cfb,
        EVP_aes_192_cfb(),
        "aes-192-cfb",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::cfb1,
        EVP_aes_192_cfb1(),
        "aes-192-cfb1",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::cfb8,
        EVP_aes_192_cfb8(),
        "aes-192-cfb8",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::ctr,
        EVP_aes_192_ctr(),
        "aes-192-ctr",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::ecb,
        EVP_aes_192_ecb(),
        "aes-192-ecb",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::gcm,
        EVP_aes_192_gcm(),
        "aes-192-gcm",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::ofb,
        EVP_aes_192_ofb(),
        "aes-192-ofb",
    },
    {
        crypt_algorithm_t::aes192,
        crypt_mode_t::wrap,
        EVP_aes_192_wrap(),
        "aes-192-wrap",
    },

    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::cbc,
        EVP_aes_256_cbc(),
        "aes-256-cbc",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::ccm,
        EVP_aes_256_ccm(),
        "aes-256-ccm",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::cfb,
        EVP_aes_256_cfb(),
        "aes-256-cfb",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::cfb1,
        EVP_aes_256_cfb1(),
        "aes-256-cfb1",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::cfb8,
        EVP_aes_256_cfb8(),
        "aes-256-cfb8",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::ctr,
        EVP_aes_256_ctr(),
        "aes-256-ctr",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::ecb,
        EVP_aes_256_ecb(),
        "aes-256-ecb",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::gcm,
        EVP_aes_256_gcm(),
        "aes-256-gcm",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::ofb,
        EVP_aes_256_ofb(),
        "aes-256-ofb",
    },
    {
        crypt_algorithm_t::aes256,
        crypt_mode_t::wrap,
        EVP_aes_256_wrap(),
        "aes-256-wrap",
    },

    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::cbc,
        EVP_aria_128_cbc(),
        "aria-128-cbc",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::ccm,
        EVP_aria_128_ccm(),
        "aria-128-ccm",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::cfb,
        EVP_aria_128_cfb(),
        "aria-128-cfb",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::cfb1,
        EVP_aria_128_cfb1(),
        "aria-128-cfb1",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::cfb8,
        EVP_aria_128_cfb8(),
        "aria-128-cfb8",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::ctr,
        EVP_aria_128_ctr(),
        "aria-128-ctr",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::ecb,
        EVP_aria_128_ecb(),
        "aria-128-ecb",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::gcm,
        EVP_aria_128_gcm(),
        "aria-128-gcm",
    },
    {
        crypt_algorithm_t::aria128,
        crypt_mode_t::ofb,
        EVP_aria_128_ofb(),
        "aria-128-ofb",
    },

    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::cbc,
        EVP_aria_192_cbc(),
        "aria-192-cbc",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::ccm,
        EVP_aria_192_ccm(),
        "aria-192-ccm",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::cfb,
        EVP_aria_192_cfb(),
        "aria-192-cfb",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::cfb1,
        EVP_aria_192_cfb1(),
        "aria-192-cfb1",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::cfb8,
        EVP_aria_192_cfb8(),
        "aria-192-cfb8",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::ctr,
        EVP_aria_192_ctr(),
        "aria-192-ctr",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::ecb,
        EVP_aria_192_ecb(),
        "aria-192-ecb",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::gcm,
        EVP_aria_192_gcm(),
        "aria-192-gcm",
    },
    {
        crypt_algorithm_t::aria192,
        crypt_mode_t::ofb,
        EVP_aria_192_ofb(),
        "aria-192-ofb",
    },

    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::cbc,
        EVP_aria_256_cbc(),
        "aria-256-cbc",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::ccm,
        EVP_aria_256_ccm(),
        "aria-256-ccm",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::cfb,
        EVP_aria_256_cfb(),
        "aria-256-cfb",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::cfb1,
        EVP_aria_256_cfb1(),
        "aria-256-cfb1",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::cfb8,
        EVP_aria_256_cfb8(),
        "aria-256-cfb8",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::ctr,
        EVP_aria_256_ctr(),
        "aria-256-ctr",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::ecb,
        EVP_aria_256_ecb(),
        "aria-256-ecb",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::gcm,
        EVP_aria_256_gcm(),
        "aria-256-gcm",
    },
    {
        crypt_algorithm_t::aria256,
        crypt_mode_t::ofb,
        EVP_aria_256_ofb(),
        "aria-256-ofb",
    },

    {
        crypt_algorithm_t::blowfish,
        crypt_mode_t::cbc,
        EVP_bf_cbc(),
        "bf-cbc",
    },
    {
        crypt_algorithm_t::blowfish,
        crypt_mode_t::cfb,
        EVP_bf_cfb(),
        "bf-cfb",
    },
    //{ crypt_algorithm_t::blowfish, crypt_mode_t::ctr, EVP_bf_ctr (), "bf-ctr", },
    {
        crypt_algorithm_t::blowfish,
        crypt_mode_t::ecb,
        EVP_bf_ecb(),
        "bf-ecb",
    },
    {
        crypt_algorithm_t::blowfish,
        crypt_mode_t::ofb,
        EVP_bf_ofb(),
        "bf-ofb",
    },

    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::cbc,
        EVP_camellia_128_cbc(),
        "camellia-128-cbc",
    },
    //{ crypt_algorithm_t::camellia128, crypt_mode_t::ccm,  EVP_camellia_128_ccm (),  "camellia-128-ccm", },
    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::cfb,
        EVP_camellia_128_cfb(),
        "camellia-128-cfb",
    },
    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::cfb1,
        EVP_camellia_128_cfb1(),
        "camellia-128-cfb1",
    },
    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::cfb8,
        EVP_camellia_128_cfb8(),
        "camellia-128-cfb8",
    },
    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::ctr,
        EVP_camellia_128_ctr(),
        "camellia-128-ctr",
    },
    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::ecb,
        EVP_camellia_128_ecb(),
        "camellia-128-ecb",
    },
    //{ crypt_algorithm_t::camellia128, crypt_mode_t::gcm,  EVP_camellia_128_gcm (),  "camellia-128-gcm", },
    {
        crypt_algorithm_t::camellia128,
        crypt_mode_t::ofb,
        EVP_camellia_128_ofb(),
        "camellia-128-ofb",
    },

    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::cbc,
        EVP_camellia_192_cbc(),
        "camellia-192-cbc",
    },
    //{ crypt_algorithm_t::camellia192, crypt_mode_t::ccm,  EVP_camellia_192_ccm (),  "camellia-192-ccm", },
    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::cfb,
        EVP_camellia_192_cfb(),
        "camellia-192-cfb",
    },
    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::cfb1,
        EVP_camellia_192_cfb1(),
        "camellia-192-cfb1",
    },
    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::cfb8,
        EVP_camellia_192_cfb8(),
        "camellia-192-cfb8",
    },
    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::ctr,
        EVP_camellia_192_ctr(),
        "camellia-192-ctr",
    },
    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::ecb,
        EVP_camellia_192_ecb(),
        "camellia-192-ecb",
    },
    //{ crypt_algorithm_t::camellia192, crypt_mode_t::gcm,  EVP_camellia_192_gcm (),  "camellia-192-gcm", },
    {
        crypt_algorithm_t::camellia192,
        crypt_mode_t::ofb,
        EVP_camellia_192_ofb(),
        "camellia-192-ofb",
    },

    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::cbc,
        EVP_camellia_256_cbc(),
        "camellia-256-cbc",
    },
    //{ crypt_algorithm_t::camellia256, crypt_mode_t::ccm,  EVP_camellia_256_ccm (),  "camellia-256-ccm", },
    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::cfb,
        EVP_camellia_256_cfb(),
        "camellia-256-cfb",
    },
    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::cfb1,
        EVP_camellia_256_cfb1(),
        "camellia-256-cfb1",
    },
    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::cfb8,
        EVP_camellia_256_cfb8(),
        "camellia-256-cfb8",
    },
    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::ctr,
        EVP_camellia_256_ctr(),
        "camellia-256-ctr",
    },
    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::ecb,
        EVP_camellia_256_ecb(),
        "camellia-256-ecb",
    },
    //{ crypt_algorithm_t::camellia256, crypt_mode_t::gcm,  EVP_camellia_256_gcm (),  "camellia-256-gcm", },
    {
        crypt_algorithm_t::camellia256,
        crypt_mode_t::ofb,
        EVP_camellia_256_ofb(),
        "camellia-256-ofb",
    },

    {
        crypt_algorithm_t::cast,
        crypt_mode_t::cbc,
        EVP_cast5_cbc(),
        "cast5-cbc",
    },
    {
        crypt_algorithm_t::cast,
        crypt_mode_t::cfb,
        EVP_cast5_cfb(),
        "cast5-cfb",
    },
    {
        crypt_algorithm_t::cast,
        crypt_mode_t::ecb,
        EVP_cast5_ecb(),
        "cast5-ecb",
    },
    {
        crypt_algorithm_t::cast,
        crypt_mode_t::ofb,
        EVP_cast5_ofb(),
        "cast5-ofb",
    },

    {
        crypt_algorithm_t::idea,
        crypt_mode_t::cbc,
        EVP_CIPHER_IDEA_CBC,
        "idea-cbc",
    },
    {
        crypt_algorithm_t::idea,
        crypt_mode_t::cfb,
        EVP_CIPHER_IDEA_CFB,
        "idea-cfb",
    },
    {
        crypt_algorithm_t::idea,
        crypt_mode_t::ecb,
        EVP_CIPHER_IDEA_ECB,
        "idea-ecb",
    },
    {
        crypt_algorithm_t::idea,
        crypt_mode_t::ofb,
        EVP_CIPHER_IDEA_OFB,
        "idea-ofb",
    },

    {
        crypt_algorithm_t::rc2,
        crypt_mode_t::cbc,
        EVP_CIPHER_RC2_CBC,
        "rc2-cbc",
    },
    {
        crypt_algorithm_t::rc2,
        crypt_mode_t::cfb,
        EVP_CIPHER_RC2_CFB,
        "rc2-cfb",
    },
    {
        crypt_algorithm_t::rc2,
        crypt_mode_t::ecb,
        EVP_CIPHER_RC2_ECB,
        "rc2-ecb",
    },
    {
        crypt_algorithm_t::rc2,
        crypt_mode_t::ofb,
        EVP_CIPHER_RC2_OFB,
        "rc2-ofb",
    },

    {
        crypt_algorithm_t::rc5,
        crypt_mode_t::cbc,
        EVP_CIPHER_RC5_CBC,
        "rc5-cbc",
    },
    {
        crypt_algorithm_t::rc5,
        crypt_mode_t::cfb,
        EVP_CIPHER_RC5_CFB,
        "rc5-cfb",
    },
    {
        crypt_algorithm_t::rc5,
        crypt_mode_t::ecb,
        EVP_CIPHER_RC5_ECB,
        "rc5-ecb",
    },
    {
        crypt_algorithm_t::rc5,
        crypt_mode_t::ofb,
        EVP_CIPHER_RC5_OFB,
        "rc5-ofb",
    },

    {
        crypt_algorithm_t::sm4,
        crypt_mode_t::cbc,
        EVP_CIPHER_SM4_CBC,
        "sm4-cbc",
    },
    {
        crypt_algorithm_t::sm4,
        crypt_mode_t::cfb,
        EVP_CIPHER_SM4_CFB,
        "sm4-cfb",
    },
    {
        crypt_algorithm_t::sm4,
        crypt_mode_t::ecb,
        EVP_CIPHER_SM4_ECB,
        "sm4-ecb",
    },
    {
        crypt_algorithm_t::sm4,
        crypt_mode_t::ofb,
        EVP_CIPHER_SM4_OFB,
        "sm4-ofb",
    },
    {
        crypt_algorithm_t::sm4,
        crypt_mode_t::ctr,
        EVP_CIPHER_SM4_CTR,
        "sm4-ctr",
    },

    {
        crypt_algorithm_t::seed,
        crypt_mode_t::cbc,
        EVP_seed_cbc(),
        "seed-cbc",
    },
    {
        crypt_algorithm_t::seed,
        crypt_mode_t::cfb,
        EVP_seed_cfb(),
        "seed-cfb",
    },
    {
        crypt_algorithm_t::seed,
        crypt_mode_t::ecb,
        EVP_seed_ecb(),
        "seed-ecb",
    },
    {
        crypt_algorithm_t::seed,
        crypt_mode_t::ofb,
        EVP_seed_ofb(),
        "seed-ofb",
    },

    {
        crypt_algorithm_t::rc4,
        crypt_mode_t::stream_cipher,
        EVP_rc4(),
        "rc4",
    },
    {
        crypt_algorithm_t::chacha20,
        crypt_mode_t::stream_cipher,
        EVP_chacha20(),
        "chacha20",
    },
    {
        crypt_algorithm_t::chacha20,
        crypt_mode_t::stream_aead,
        EVP_chacha20_poly1305(),
        "chacha20-poly1305",
    },
};

/* something wrong EVP_CIPHER_CTX_iv_length, EVP_CIPHER_CTX_block_size (openssl-1.1.1) */
const hint_blockcipher_t hint_blockciphers[] = {
    // 16 (128), 24 (192), 32 (256)

    {
        crypt_algorithm_t::aes128,
        16,
        16,
        16,
        16,
    },
    {
        crypt_algorithm_t::aes192,
        24,
        16,
        16,
        24,
    },
    {
        crypt_algorithm_t::aes256,
        32,
        16,
        16,
        32,
    },
    {
        crypt_algorithm_t::blowfish,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::aria128,
        16,
        16,
        16,
    },
    {
        crypt_algorithm_t::aria192,
        24,
        16,
        16,
    },
    {
        crypt_algorithm_t::aria256,
        32,
        16,
        16,
    },

    {
        crypt_algorithm_t::camellia128,
        16,
        16,
        16,
    },
    {
        crypt_algorithm_t::camellia192,
        24,
        16,
        16,
    },
    {
        crypt_algorithm_t::camellia256,
        32,
        16,
        16,
    },

    {
        crypt_algorithm_t::cast,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::idea,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::rc2,
        8,
        8,
        8,
    },

    {
        crypt_algorithm_t::rc5,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::seed,
        16,
        16,
        16,
    },

    {
        crypt_algorithm_t::sm4,
        16,
        16,
        16,
    },

    {
        crypt_algorithm_t::rc4,
        0,
        12,
        0,
    },
    {
        crypt_algorithm_t::chacha20,
        32,
        12,
        0,
    },
};

const openssl_evp_md_method_t evp_md_methods[] = {
    {
        hash_algorithm_t::md4,
        EVP_md4(),
        "md4",
    },
    {
        hash_algorithm_t::md5,
        EVP_md5(),
        "md5",
    },

    {
        hash_algorithm_t::sha1,
        EVP_sha1(),
        "sha1",
    },

    {
        hash_algorithm_t::sha2_224,
        EVP_sha224(),
        "sha224",
    },
    {
        hash_algorithm_t::sha2_256,
        EVP_sha256(),
        "sha256",
    },
    {
        hash_algorithm_t::sha2_384,
        EVP_sha384(),
        "sha384",
    },
    {
        hash_algorithm_t::sha2_512,
        EVP_sha512(),
        "sha512",
    },
    {
        hash_algorithm_t::sha2_512_224,
        EVP_sha512_224(),
        "sha2-512/224",
    },
    {
        hash_algorithm_t::sha2_512_256,
        EVP_sha512_256(),
        "sha2-512/256",
    },

    {
        hash_algorithm_t::sha3_224,
        EVP_sha3_224(),
        "sha3-224",
    },
    {
        hash_algorithm_t::sha3_256,
        EVP_sha3_256(),
        "sha3-256",
    },
    {
        hash_algorithm_t::sha3_384,
        EVP_sha3_384(),
        "sha3-384",
    },
    {
        hash_algorithm_t::sha3_512,
        EVP_sha3_512(),
        "sha3-512",
    },

    {
        hash_algorithm_t::shake128,
        EVP_shake128(),
        "shake128",
    },
    {
        hash_algorithm_t::shake256,
        EVP_shake256(),
        "shake256",
    },

    {
        hash_algorithm_t::blake2b_512,
        EVP_blake2b512(),
        "blake2b512",
    },
    {
        hash_algorithm_t::blake2s_256,
        EVP_blake2s256(),
        "blake2s256",
    },

    {
        hash_algorithm_t::ripemd160,
        EVP_ripemd160(),
        "ripemd160",
    },

    {
        hash_algorithm_t::whirlpool,
        EVP_whirlpool(),
        "whirlpool",
    },
};

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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
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
        crypto_kty_t::kty_hmac,
        crypto_kty_t::kty_unknown,
        0,
        crypt_algorithm_t::aes256,
        crypt_mode_t::gcm,
        32,
    },
};

const hint_signature_t hint_signatures[] = {
    {
        crypt_sig_t::sig_hs256,
        jws_t::jws_hs256,
        jws_group_t::jws_group_hmac,
        crypto_kty_t::kty_hmac,
        "HS256",
        hash_algorithm_t::sha2_256,
        1,
        NID_hmac,
    },
    {
        crypt_sig_t::sig_hs384,
        jws_t::jws_hs384,
        jws_group_t::jws_group_hmac,
        crypto_kty_t::kty_hmac,
        "HS384",
        hash_algorithm_t::sha2_384,
        1,
        NID_hmac,
    },
    {
        crypt_sig_t::sig_hs512,
        jws_t::jws_hs512,
        jws_group_t::jws_group_hmac,
        crypto_kty_t::kty_hmac,
        "HS512",
        hash_algorithm_t::sha2_512,
        1,
        NID_hmac,
    },
    {
        crypt_sig_t::sig_rs256,
        jws_t::jws_rs256,
        jws_group_t::jws_group_rsassa_pkcs15,
        crypto_kty_t::kty_rsa,
        "RS256",
        hash_algorithm_t::sha2_256,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_rs384,
        jws_t::jws_rs384,
        jws_group_t::jws_group_rsassa_pkcs15,
        crypto_kty_t::kty_rsa,
        "RS384",
        hash_algorithm_t::sha2_384,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_rs512,
        jws_t::jws_rs512,
        jws_group_t::jws_group_rsassa_pkcs15,
        crypto_kty_t::kty_rsa,
        "RS512",
        hash_algorithm_t::sha2_512,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_rs1,
        jws_t::jws_unknown,
        jws_group_t::jws_group_rsassa_pkcs15,
        crypto_kty_t::kty_rsa,
        nullptr,
        hash_algorithm_t::sha1,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_es256,
        jws_t::jws_es256,
        jws_group_t::jws_group_ecdsa,
        crypto_kty_t::kty_ec,
        "ES256",
        hash_algorithm_t::sha2_256,
        1,
        NID_X9_62_prime256v1,
    },
    {
        crypt_sig_t::sig_es384,
        jws_t::jws_es384,
        jws_group_t::jws_group_ecdsa,
        crypto_kty_t::kty_ec,
        "ES384",
        hash_algorithm_t::sha2_384,
        1,
        NID_secp384r1,
    },
    {
        crypt_sig_t::sig_es512,
        jws_t::jws_es512,
        jws_group_t::jws_group_ecdsa,
        crypto_kty_t::kty_ec,
        "ES512",
        hash_algorithm_t::sha2_512,
        1,
        NID_secp521r1,
    },
    {
        crypt_sig_t::sig_ps256,
        jws_t::jws_ps256,
        jws_group_t::jws_group_rsassa_pss,
        crypto_kty_t::kty_rsa,
        "PS256",
        hash_algorithm_t::sha2_256,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_ps384,
        jws_t::jws_ps384,
        jws_group_t::jws_group_rsassa_pss,
        crypto_kty_t::kty_rsa,
        "PS384",
        hash_algorithm_t::sha2_384,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_ps512,
        jws_t::jws_ps512,
        jws_group_t::jws_group_rsassa_pss,
        crypto_kty_t::kty_rsa,
        "PS512",
        hash_algorithm_t::sha2_512,
        1,
        NID_rsaEncryption,
    },
    {
        crypt_sig_t::sig_eddsa,
        jws_t::jws_eddsa,
        jws_group_t::jws_group_eddsa,
        crypto_kty_t::kty_okp,
        "EdDSA",
        hash_algorithm_t::hash_alg_unknown,
        2,
        NID_ED25519,
        NID_ED448,
    },
};

const hint_cose_algorithm_t hint_cose_algorithms[] = {
    {
        cose_alg_t::cose_aes_128_kw,  // -3
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aeskw,
    },
    {
        cose_alg_t::cose_aes_192_kw,  // -4
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aeskw,
    },
    {
        cose_alg_t::cose_aes_256_kw,  // -5
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aeskw,
    },
    {
        cose_alg_t::cose_direct,  // -6
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_direct,
    },
    {
        cose_alg_t::cose_es256,  // -7
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdsa,
    },
    {
        cose_alg_t::cose_es384,  // -35
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdsa,
    },
    {
        cose_alg_t::cose_es512,  // -36
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdsa,
    },
    {
        cose_alg_t::cose_eddsa,  // -8
        crypto_kty_t::kty_okp,
        cose_group_t::cose_group_eddsa,
    },
    {
        cose_alg_t::cose_direct_hkdf_sha_256,  // -10
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_direct_hkdf_sha,
        16,
        "sha256",
    },
    {
        cose_alg_t::cose_direct_hkdf_sha_512,  // -11
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_direct_hkdf_sha,
        32,
        "sha512",
    },
    {
        cose_alg_t::cose_direct_hkdf_aes_128,  // -12
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_direct_hkdf_aes,
        16,
        "aes-128-wrap",
    },
    {
        cose_alg_t::cose_direct_hkdf_aes_256,  // -13
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_direct_hkdf_aes,
        32,
        "aes-256-wrap",
    },
    {
        cose_alg_t::cose_sha1,  // -14
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_sha256_64,  // -15
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_sha256,  // -16
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_sha512_256,  // -17
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_sha384,  // -43
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_sha512,  // -44
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_shake128,  // -18
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_shake256,  // -45
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_sha,
    },
    {
        cose_alg_t::cose_ecdh_es_hkdf_256,  // -25
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_es_hkdf,
        16,
        "sha256",
    },
    {
        cose_alg_t::cose_ecdh_es_hkdf_512,  // -26
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_es_hkdf,
        32,
        "sha512",
    },
    {
        cose_alg_t::cose_ecdh_ss_hkdf_256,  // -27
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_ss_hkdf,
        16,
        "sha256",
    },
    {
        cose_alg_t::cose_ecdh_ss_hkdf_512,  // -28
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_ss_hkdf,
        32,
        "sha512",
    },
    {
        cose_alg_t::cose_ecdh_es_a128kw,  // -29
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_es_aeskw,
        16,
        "aes-128-wrap",
    },
    {
        cose_alg_t::cose_ecdh_es_a192kw,  // -30
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_es_aeskw,
        24,
        "aes-192-wrap",
    },
    {
        cose_alg_t::cose_ecdh_es_a256kw,  // -31
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_es_aeskw,
        32,
        "aes-256-wrap",
    },
    {
        cose_alg_t::cose_ecdh_ss_a128kw,  // -32
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_ss_aeskw,
        16,
        "aes-128-wrap",
    },
    {
        cose_alg_t::cose_ecdh_ss_a192kw,  // -33
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_ss_aeskw,
        24,
        "aes-192-wrap",
    },
    {
        cose_alg_t::cose_ecdh_ss_a256kw,  // -34
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdh_ss_aeskw,
        32,
        "aes-256-wrap",
    },
    {
        cose_alg_t::cose_ps256,  // -37
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pss,
    },
    {
        cose_alg_t::cose_ps384,  // -38
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pss,
    },
    {
        cose_alg_t::cose_ps512,  // -39
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pss,
    },
    {
        cose_alg_t::cose_rsaes_oaep_sha1,  // -40
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsa_oaep,
    },
    {
        cose_alg_t::cose_rsaes_oaep_sha256,  // -41
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsa_oaep,
    },
    {
        cose_alg_t::cose_rsaes_oaep_sha512,  // -42
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsa_oaep,
    },
    {
        cose_alg_t::cose_es256k,  // -47
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_ecdsa,
    },
    {
        cose_alg_t::cose_rs256,  // -257
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pkcs15,
    },
    {
        cose_alg_t::cose_rs384,  // -258
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pkcs15,
    },
    {
        cose_alg_t::cose_rs512,  // -259,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pkcs15,
    },
    {
        cose_alg_t::cose_rs1,  // -65535,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_rsassa_pkcs15,
    },
    {
        cose_alg_t::cose_aes_128_gcm,  // 1
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesgcm,
        0,
        "aes-128-gcm",
    },
    {
        cose_alg_t::cose_aes_192_gcm,  // 2
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesgcm,
        0,
        "aes-192-gcm",
    },
    {
        cose_alg_t::cose_aes_256_gcm,  // 3
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesgcm,
        0,
        "aes-256-gcm",
    },
    {
        cose_alg_t::cose_hs256_64,  // 4,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_hmac,
    },
    {
        cose_alg_t::cose_hs256,  // 5,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_hmac,
    },
    {
        cose_alg_t::cose_hs384,  // 6,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_hmac,
    },
    {
        cose_alg_t::cose_hs512,  // 7,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_hmac,
    },
    {
        cose_alg_t::cose_aes_ccm_16_64_128,  // 10,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_16_64_256,  // 11,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_64_64_128,  // 12,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_64_64_256,  // 13,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_16_128_128,  // 30,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_16_128_256,  // 31,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_64_128_128,  // 32,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_ccm_64_128_256,  // 33,
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aesccm,
    },
    {
        cose_alg_t::cose_aes_cbc_mac_128_64,  // 14
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aescbc_mac,
    },
    {
        cose_alg_t::cose_aes_cbc_mac_256_64,  // 15
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aescbc_mac,
    },
    {
        cose_alg_t::cose_aes_cbc_mac_128_128,  // 25
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aescbc_mac,
    },
    {
        cose_alg_t::cose_aes_cbc_mac_256_128,  // 26
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_aescbc_mac,
    },
    {
        cose_alg_t::cose_chacha20_poly1305,  // 24
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_chacha20,
    },
    {
        cose_alg_t::cose_iv_generation,  // 34
        crypto_kty_t::kty_hmac,
        cose_group_t::cose_group_iv,
    },
};

/*
 * Standard curve database - NIST, ANSI X9.62 & X9.63, SECG, ...
 * https://neuromancer.sk/std/
 */
const hint_curve_t hint_curves[] = {
    {
        NID_X9_62_prime256v1,
        cose_ec_curve_t::cose_ec_p256,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-256",
        "prime256v1",
        "secp256r1",
    },
    {
        NID_secp384r1,
        cose_ec_curve_t::cose_ec_p384,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-384",
        "ansip384r1",
        "secp384r1",
    },
    {
        NID_secp521r1,
        cose_ec_curve_t::cose_ec_p521,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-521",
        "ansip521r1",
        "secp521r1",
    },
    {
        NID_ED25519,
        cose_ec_curve_t::cose_ec_ed25519,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_sig,
        "Ed25519",
    },
    {
        NID_ED448,
        cose_ec_curve_t::cose_ec_ed448,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_sig,
        "Ed448",
    },
    {
        NID_X25519,
        cose_ec_curve_t::cose_ec_x25519,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_enc,
        "X25519",
    },
    {
        NID_X448,
        cose_ec_curve_t::cose_ec_x448,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_enc,
        "X448",
    },
    {
        NID_secp224r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-224",
        "ansip224r1",
        "secp224r1",
        "wap-wsg-idm-ecid-wtls12",
    },

    // openssl-3.0
    {
        NID_X9_62_prime192v1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-192",
        "prime192v1",
        "secp192r1",
    },
    {
        NID_sect163k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-163",
        nullptr,
        "sect163k1",
    },
    {
        NID_sect233k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-233",
        "ansit233k1",
        "sect233k1",
        "wap-wsg-idm-ecid-wtls10",
    },
    {
        NID_sect283k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-283",
        "ansit283k1",
        "sect283k1",
    },
    {
        NID_sect409k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-409",
        "ansit409k1",
        "sect409k1",
    },
    {
        NID_sect571k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-571",
        "ansit571k1",
        "sect571k1",
    },
    {
        NID_sect163r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-163",
        "ansit163r2",
        "sect163r2",
    },
    {
        NID_sect233r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-233",
        "ansit233r1",
        "sect233r1",
        "wap-wsg-idm-ecid-wtls11",
    },
    {
        NID_sect283r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-283",
        "ansit283r1",
        "sect283r1",
    },
    {
        NID_sect409r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-409",
        "ansit409r1",
        "sect409r1",
    },
    {
        NID_sect571r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-571",
        "ansit571r1",
        "sect571r1",
    },
};

const hint_kty_name_t hint_kty_names[] = {
    {
        crypto_kty_t::kty_hmac,
        "oct",
    },
    {
        crypto_kty_t::kty_rsa,
        "RSA",
    },
    {
        crypto_kty_t::kty_ec,
        "EC",
    },
    {
        crypto_kty_t::kty_okp,
        "OKP",
    },
};

const size_t sizeof_hint_jose_algorithms = RTL_NUMBER_OF(hint_jose_algorithms);
const size_t sizeof_hint_jose_encryptions = RTL_NUMBER_OF(hint_jose_encryptions);
const size_t sizeof_hint_signatures = RTL_NUMBER_OF(hint_signatures);
const size_t sizeof_hint_cose_algorithms = RTL_NUMBER_OF(hint_cose_algorithms);
const size_t sizeof_hint_curves = RTL_NUMBER_OF(hint_curves);
const size_t sizeof_hint_kty_names = RTL_NUMBER_OF(hint_kty_names);

crypto_advisor crypto_advisor::_instance;

crypto_advisor* crypto_advisor::get_instance() { return &_instance; }

crypto_advisor::~crypto_advisor() { cleanup(); }

crypto_advisor::crypto_advisor() : _flag(0) { build_if_necessary(); }

return_t crypto_advisor::build_if_necessary() {
    return_t ret = errorcode_t::success;
    uint32 i = 0;

    if (0 == _flag) {
        for (i = 0; i < RTL_NUMBER_OF(hint_blockciphers); i++) {
            const hint_blockcipher_t* item = hint_blockciphers + i;
            _blockcipher_map.insert(std::make_pair(item->_alg, item));
        }
        for (i = 0; i < RTL_NUMBER_OF(evp_cipher_methods); i++) {
            const openssl_evp_cipher_method_t* item = evp_cipher_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(nullptr, item->_fetchname, nullptr);
            if (nullptr == evp_cipher) {
                __trace(errorcode_t::debug, "%s", item->_fetchname);
            }
            _cipher_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(item->_algorithm, item->_mode), evp_cipher));
            _evp_cipher_map.insert(std::make_pair(evp_cipher, item));
#else
            _cipher_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(item->_algorithm, item->_mode), (EVP_CIPHER*)item->_cipher));
            _evp_cipher_map.insert(std::make_pair(item->_cipher, item));
#endif
            _cipher_fetch_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(item->_algorithm, item->_mode), item));
            _cipher_byname_map.insert(std::make_pair(item->_fetchname, item));
        }
        for (i = 0; i < RTL_NUMBER_OF(evp_md_methods); i++) {
            const openssl_evp_md_method_t* item = evp_md_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            EVP_MD* evp_md = EVP_MD_fetch(nullptr, item->_fetchname, nullptr);
            if (nullptr == evp_md) {
                __trace(errorcode_t::debug, "%s", item->_fetchname);
            }
            _md_map.insert(std::make_pair(item->_algorithm, evp_md));
#else
            _md_map.insert(std::make_pair(item->_algorithm, (EVP_MD*)item->_evp_md));
#endif
            _md_fetch_map.insert(std::make_pair(item->_algorithm, item));
            _md_byname_map.insert(std::make_pair(item->_fetchname, item));
        }

        ERR_clear_error();  // errors while EVP_CIPHER_fetch, EVP_MD_fetch

        for (i = 0; i < sizeof_hint_jose_algorithms; i++) {
            const hint_jose_encryption_t* item = hint_jose_algorithms + i;
            _alg_map.insert(std::make_pair(item->type, item));
            if (item->alg_name) {
                _alg_byname_map.insert(std::make_pair(item->alg_name, item));
            }
        }
        for (i = 0; i < sizeof_hint_jose_encryptions; i++) {
            const hint_jose_encryption_t* item = hint_jose_encryptions + i;
            _enc_map.insert(std::make_pair(item->type, item));
            if (item->alg_name) {
                _enc_byname_map.insert(std::make_pair(item->alg_name, item));
            }
        }
        for (i = 0; i < sizeof_hint_signatures; i++) {
            const hint_signature_t* item = hint_signatures + i;
            _crypt_sig_map.insert(std::make_pair(item->sig_type, item));
            if (item->jws_name) {
                _sig_byname_map.insert(std::make_pair(item->jws_name, item));
            }
            if (item->jws_type) {
                _jose_sig_map.insert(std::make_pair(item->jws_type, item));
                _sig2jws_map.insert(std::make_pair(item->sig_type, item->jws_type));
            }
        }
        for (i = 0; i < sizeof_hint_signatures; i++) {
            const hint_signature_t* item = hint_signatures + i;
            for (uint midx = 0; midx < item->count; midx++) {
                _sig_bynid_map.insert(std::make_pair(item->nid[midx], item));
            }
        }
        for (i = 0; i < sizeof_hint_cose_algorithms; i++) {
            const hint_cose_algorithm_t* item = hint_cose_algorithms + i;
            _cose_alg_map.insert(std::make_pair(item->alg, item));
        }
        for (i = 0; i < sizeof_hint_curves; i++) {
            const hint_curve_t* item = hint_curves + i;
            _nid_bycurve_map.insert(std::make_pair(item->name, item));
            _curve_bynid_map.insert(std::make_pair(item->nid, item));
        }

        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_ec, cose_kty_t::cose_kty_ec2));
        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_hmac, cose_kty_t::cose_kty_symm));
        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_okp, cose_kty_t::cose_kty_okp));
        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_rsa, cose_kty_t::cose_kty_rsa));

        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_ec2, crypto_kty_t::kty_ec));
        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_symm, crypto_kty_t::kty_hmac));
        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_okp, crypto_kty_t::kty_okp));
        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_rsa, crypto_kty_t::kty_rsa));

        struct _sig2cose {
            crypt_sig_t sig;
            jws_t jws;
            cose_alg_t cose;
        };
        struct _sig2cose sig2cose[] = {
            {crypt_sig_t::sig_hs256, jws_t::jws_hs256, cose_alg_t::cose_hs256}, {crypt_sig_t::sig_hs384, jws_t::jws_hs384, cose_alg_t::cose_hs384},
            {crypt_sig_t::sig_hs512, jws_t::jws_hs512, cose_alg_t::cose_hs512}, {crypt_sig_t::sig_rs256, jws_t::jws_rs256, cose_alg_t::cose_rs256},
            {crypt_sig_t::sig_rs384, jws_t::jws_rs384, cose_alg_t::cose_rs384}, {crypt_sig_t::sig_rs512, jws_t::jws_rs512, cose_alg_t::cose_rs512},
            {crypt_sig_t::sig_es256, jws_t::jws_es256, cose_alg_t::cose_es256}, {crypt_sig_t::sig_es384, jws_t::jws_es384, cose_alg_t::cose_es384},
            {crypt_sig_t::sig_es512, jws_t::jws_es512, cose_alg_t::cose_es512}, {crypt_sig_t::sig_ps256, jws_t::jws_ps256, cose_alg_t::cose_ps256},
            {crypt_sig_t::sig_ps384, jws_t::jws_ps384, cose_alg_t::cose_ps384}, {crypt_sig_t::sig_ps512, jws_t::jws_ps512, cose_alg_t::cose_ps512},
            {crypt_sig_t::sig_eddsa, jws_t::jws_eddsa, cose_alg_t::cose_eddsa},
        };
        struct _sig2cose cose2sig[] = {
            {crypt_sig_t::sig_hs256, jws_t::jws_hs256, cose_alg_t::cose_hs256_64},
        };
        for (i = 0; i < RTL_NUMBER_OF(sig2cose); i++) {
            _sig2jws_map.insert(std::make_pair(sig2cose[i].sig, sig2cose[i].jws));
            _jws2sig_map.insert(std::make_pair(sig2cose[i].jws, sig2cose[i].sig));
            if (cose_alg_t::cose_unknown != sig2cose[i].cose) {
                _sig2cose_map.insert(std::make_pair(sig2cose[i].sig, sig2cose[i].cose));
            }
            _cose2sig_map.insert(std::make_pair(sig2cose[i].cose, sig2cose[i].sig));
        }
        for (i = 0; i < RTL_NUMBER_OF(cose2sig); i++) {
            _cose2sig_map.insert(std::make_pair(cose2sig[i].cose, cose2sig[i].sig));
        }

        for (i = 0; i < RTL_NUMBER_OF(hint_curves); i++) {
            _nid2curve_map.insert(std::make_pair(hint_curves[i].nid, hint_curves[i].cose_crv));
            if (hint_curves[i].cose_crv) {
                _curve2nid_map.insert(std::make_pair(hint_curves[i].cose_crv, hint_curves[i].nid));
            }
        }

        _flag = 1;
    }
    return ret;
}

return_t crypto_advisor::cleanup() {
    return_t ret = errorcode_t::success;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    cipher_map_t::iterator iter_cipher;
    for (iter_cipher = _cipher_map.begin(); iter_cipher != _cipher_map.end(); iter_cipher++) {
        EVP_CIPHER_free(iter_cipher->second);
    }
    md_map_t::iterator iter_md;
    for (iter_md = _md_map.begin(); iter_md != _md_map.end(); iter_md++) {
        EVP_MD_free(iter_md->second);
    }
#endif

    return ret;
}

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher(crypt_algorithm_t alg) {
    const hint_blockcipher_t* item = nullptr;
    maphint<uint32, const hint_blockcipher_t*> hint(_blockcipher_map);

    hint.find(alg, &item);
    return item;
}

const hint_blockcipher_t* crypto_advisor::find_evp_cipher(const EVP_CIPHER* cipher) {
    const hint_blockcipher_t* blockcipher = nullptr;
    return_t ret = errorcode_t::success;

    __try2 {
        crypt_algorithm_t alg = crypt_algorithm_t::crypt_alg_unknown;
        crypt_mode_t mode = crypt_mode_t::crypt_mode_unknown;
        ret = find_evp_cipher(cipher, alg, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        blockcipher = hintof_blockcipher(alg);
    }
    __finally2 {
        // do nothing
    }
    return blockcipher;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    EVP_CIPHER* ret_value = nullptr;
    uint32 key = CRYPT_CIPHER_VALUE(algorithm, mode);
    maphint<uint32, EVP_CIPHER*> hint(_cipher_map);

    hint.find(key, &ret_value);
    return ret_value;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher(const char* name) {
    const EVP_CIPHER* ret_value = nullptr;

    if (name) {
        maphint<std::string, const openssl_evp_cipher_method_t*> hint(_cipher_byname_map);
        const openssl_evp_cipher_method_t* item = nullptr;
        hint.find(name, &item);
        if (item) {
            ret_value = _cipher_map[CRYPT_CIPHER_VALUE(item->_algorithm, item->_mode)];
        }
    }
    return ret_value;
}

return_t crypto_advisor::find_evp_cipher(const char* name, crypt_algorithm_t& algorithm, crypt_mode_t& mode) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        maphint<std::string, const openssl_evp_cipher_method_t*> hint(_cipher_byname_map);
        const openssl_evp_cipher_method_t* item = nullptr;
        ret = hint.find(name, &item);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        algorithm = item->_algorithm;
        mode = item->_mode;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::find_evp_cipher(const EVP_CIPHER* cipher, crypt_algorithm_t& algorithm, crypt_mode_t& mode) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const openssl_evp_cipher_method_t* method = nullptr;
        maphint<const EVP_CIPHER*, const openssl_evp_cipher_method_t*> hint(_evp_cipher_map);

        ret = hint.find(cipher, &method);
        if (errorcode_t::success == ret) {
            algorithm = method->_algorithm;
            mode = method->_mode;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

const char* crypto_advisor::nameof_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    return_t ret = errorcode_t::success;
    const char* ret_value = nullptr;

    __try2 {
        uint32 key = CRYPT_CIPHER_VALUE(algorithm, mode);
        const openssl_evp_cipher_method_t* item = nullptr;
        maphint<uint32, const openssl_evp_cipher_method_t*> hint(_cipher_fetch_map);

        ret = hint.find(key, &item);
        if (errorcode_t::success == ret) {
            ret_value = item->_fetchname;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(hash_algorithm_t algorithm) {
    EVP_MD* ret_value = nullptr;
    maphint<uint32, EVP_MD*> hint(_md_map);

    hint.find(algorithm, &ret_value);
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(crypt_sig_t sig) {
    const EVP_MD* ret_value = nullptr;
    const hint_signature_t* item = nullptr;
    maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = find_evp_md(item->alg);
    }
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(jws_t sig) {
    const EVP_MD* ret_value = nullptr;
    const hint_signature_t* item = nullptr;
    maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = find_evp_md(item->alg);
    }
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(const char* name) {
    const EVP_MD* ret_value = nullptr;

    if (name) {
        maphint<std::string, const openssl_evp_md_method_t*> hint(_md_byname_map);
        const openssl_evp_md_method_t* item = nullptr;
        hint.find(name, &item);
        if (item) {
            ret_value = _md_map[item->_algorithm];
        }
    }
    return ret_value;
}

return_t crypto_advisor::find_evp_md(const char* name, hash_algorithm_t& algorithm) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        maphint<std::string, const openssl_evp_md_method_t*> hint(_md_byname_map);
        const openssl_evp_md_method_t* item = nullptr;
        ret = hint.find(name, &item);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        algorithm = item->_algorithm;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

hash_algorithm_t crypto_advisor::get_algorithm(crypt_sig_t sig) {
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    const hint_signature_t* item = nullptr;
    maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = item->alg;
    }
    return ret_value;
}

hash_algorithm_t crypto_advisor::get_algorithm(jws_t sig) {
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    const hint_signature_t* item = nullptr;
    maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = item->alg;
    }
    return ret_value;
}

const char* crypto_advisor::nameof_md(hash_algorithm_t algorithm) {
    const char* ret_value = nullptr;
    const openssl_evp_md_method_t* item = nullptr;
    maphint<uint32, const openssl_evp_md_method_t*> hint(_md_fetch_map);

    hint.find(algorithm, &item);
    if (item) {
        ret_value = item->_fetchname;
    }
    return ret_value;
}

#if __cplusplus >= 201103L  // c++11
return_t crypto_advisor::jose_for_each_algorithm(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    std::for_each(hint_jose_algorithms, hint_jose_algorithms + RTL_NUMBER_OF(hint_jose_algorithms),
                  [&](const hint_jose_encryption_t& item) { return f(&item, user); });
    return ret;
}

return_t crypto_advisor::jose_for_each_encryption(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    std::for_each(hint_jose_encryptions, hint_jose_encryptions + RTL_NUMBER_OF(hint_jose_encryptions),
                  [&](const hint_jose_encryption_t& item) { return f(&item, user); });
    return ret;
}

return_t crypto_advisor::jose_for_each_signature(std::function<void(const hint_signature_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    std::for_each(hint_signatures, hint_signatures + RTL_NUMBER_OF(hint_signatures), [&](const hint_signature_t& item) { return f(&item, user); });
    return ret;
}
#endif

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(jwa_t alg) {
    const hint_jose_encryption_t* item = nullptr;
    maphint<uint32, const hint_jose_encryption_t*> hint(_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(jwe_t enc) {
    const hint_jose_encryption_t* item = nullptr;
    maphint<uint32, const hint_jose_encryption_t*> hint(_enc_map);

    hint.find(enc, &item);
    return item;
}

const hint_signature_t* crypto_advisor::hintof_signature(crypt_sig_t sig) {
    const hint_signature_t* item = nullptr;
    maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(jws_t sig) {
    const hint_signature_t* item = nullptr;
    maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    return item;
}

const hint_cose_algorithm_t* crypto_advisor::hintof_cose_algorithm(cose_alg_t alg) {
    const hint_cose_algorithm_t* item = nullptr;
    maphint<uint32, const hint_cose_algorithm_t*> hint(_cose_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve_nid(uint32 nid) {
    const hint_curve_t* item = nullptr;
    maphint<uint32, const hint_curve_t*> hint(_curve_bynid_map);

    hint.find(nid, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(const char* alg) {
    const hint_jose_encryption_t* item = nullptr;

    if (alg) {
        maphint<std::string, const hint_jose_encryption_t*> hint(_alg_byname_map);
        hint.find(alg, &item);
    }

    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(const char* enc) {
    const hint_jose_encryption_t* item = nullptr;

    if (enc) {
        maphint<std::string, const hint_jose_encryption_t*> hint(_enc_byname_map);
        hint.find(enc, &item);
    }

    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(const char* sig) {
    const hint_signature_t* item = nullptr;

    if (sig) {
        maphint<std::string, const hint_signature_t*> hint(_sig_byname_map);
        hint.find(sig, &item);
    }
    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve(const char* curve) {
    const hint_curve_t* item = nullptr;

    if (curve) {
        maphint<std::string, const hint_curve_t*> hint(_nid_bycurve_map);
        hint.find(curve, &item);
    }

    return item;
}

const char* crypto_advisor::nameof_jose_algorithm(jwa_t alg) {
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_encryption(jwe_t enc) {
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_signature(jws_t sig) {
    const char* name = nullptr;

    const hint_signature_t* item = hintof_jose_signature(sig);

    if (item) {
        name = item->jws_name;
    }
    return name;
}

return_t crypto_advisor::typeof_jose_algorithm(const char* alg, jwa_t& type) {
    return_t ret = errorcode_t::success;

    type = jwa_t::jwa_unknown;
    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        type = (jwa_t)item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_encryption(const char* enc, jwe_t& type) {
    return_t ret = errorcode_t::success;

    type = jwe_t::jwe_unknown;
    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        type = (jwe_t)item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_signature(const char* sig, jws_t& type) {
    return_t ret = errorcode_t::success;

    type = jws_t::jws_unknown;
    const hint_signature_t* item = hintof_jose_signature(sig);

    if (item) {
        type = (jws_t)item->jws_type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::nidof_ec_curve(const char* curve, uint32& nid) {
    return_t ret = errorcode_t::success;

    __try2 {
        nid = 0;

        if (nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_curve_t* item = hintof_curve(curve);
        if (item) {
            nid = item->nid;
        } else {
            ret = errorcode_t::not_found;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::ktyof_ec_curve(const char* curve, uint32& kty) {
    return_t ret = errorcode_t::success;

    __try2 {
        kty = 0;

        if (nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_curve_t* item = hintof_curve(curve);
        if (item) {
            kty = item->kty;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::ktyof_ec_curve(EVP_PKEY* pkey, std::string& kty) {
    return_t ret = errorcode_t::success;

    __try2 {
        kty.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);
        const hint_curve_t* item = hintof_curve_nid(nid);
        if (item) {
            for (uint32 i = 0; i < sizeof_hint_kty_names; i++) {
                const hint_kty_name_t* k = hint_kty_names + i;
                if (k->kty == item->kty) {
                    kty = k->name;
                    break;
                }
            }
        } else {
            ret = errorcode_t::not_found;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::nameof_ec_curve(EVP_PKEY* pkey, std::string& name) {
    return_t ret = errorcode_t::success;
    uint32 nid = 0;

    name.clear();

    if (kindof_ecc(pkey)) {
        nidof_evp_pkey(pkey, nid);

        const hint_curve_t* item = nullptr;
        maphint<uint32, const hint_curve_t*> hint(_curve_bynid_map);
        ret = hint.find(nid, &item);
        if (errorcode_t::success == ret) {
            name = item->name;
        }
    }
    return ret;
}

bool crypto_advisor::is_kindof(EVP_PKEY* pkey, const char* alg) {
    bool test = false;

    __try2 {
        const hint_jose_encryption_t* hint_alg = hintof_jose_algorithm(alg);
        if (hint_alg) {
            test = is_kindof(pkey, (jwa_t)hint_alg->type);
            if (test) {
                __leave2;
            }
        }
        const hint_signature_t* hint_sig = hintof_jose_signature(alg);
        if (hint_sig) {
            test = is_kindof(pkey, hint_sig->jws_type);
            if (test) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof(EVP_PKEY* pkey, jwa_t alg) {
    bool test = false;

    __try2 {
        const hint_jose_encryption_t* hint_enc = hintof_jose_algorithm(alg);
        if (nullptr == hint_enc) {
            __leave2;
        }
        crypto_kty_t kty = typeof_crypto_key(pkey);
        bool cmp1 = (hint_enc->kty == kty);
        bool cmp2 = (hint_enc->alt == crypto_kty_t::kty_unknown) ? true : (hint_enc->alt == kty);
        test = (cmp1 || cmp2);
    }
    __finally2 {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof(EVP_PKEY* pkey, crypt_sig_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        // uint32 type = EVP_PKEY_id (pkey);
        crypto_kty_t kty = typeof_crypto_key(pkey);
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);

        const hint_signature_t* hint = hintof_signature(sig);
        bool cond1 = (hint->sig_type == sig);
        if (false == cond1) {
            __leave2;
        }
        bool cond2 = (hint->kty == kty);
        if (false == cond2) {
            __leave2;
        }
        bool cond3 = false;
        for (uint32 i = 0; i < hint->count; i++) {
            if (hint->nid[i] == nid) {
                cond3 = true;
                break;
            }
        }
        test = (cond1 && cond2 && cond3);
    }
    __finally2 {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof(EVP_PKEY* pkey, jws_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        // uint32 type = EVP_PKEY_id (pkey);
        crypto_kty_t kty = typeof_crypto_key(pkey);
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);

        const hint_signature_t* hint = hintof_jose_signature(sig);
        bool cond1 = (hint->jws_type == sig);
        if (false == cond1) {
            __leave2;
        }
        bool cond2 = (hint->kty == kty);
        if (false == cond2) {
            __leave2;
        }
        bool cond3 = false;
        for (uint32 i = 0; i < hint->count; i++) {
            if (hint->nid[i] == nid) {
                cond3 = true;
                break;
            }
        }
        test = (cond1 && cond2 && cond3);
    }
    __finally2 {
        // do nothing
    }
    return test;
}

cose_kty_t crypto_advisor::ktyof(crypto_kty_t kty) {
    cose_kty_t cose_kty = cose_kty_t::cose_kty_unknown;
    maphint<crypto_kty_t, cose_kty_t> hint(_kty2cose_map);

    hint.find(kty, &cose_kty);
    return cose_kty;
}

crypto_kty_t crypto_advisor::ktyof(cose_kty_t kty) {
    crypto_kty_t crypto_kty = crypto_kty_t::kty_unknown;
    maphint<cose_kty_t, crypto_kty_t> hint(_cose2kty_map);

    hint.find(kty, &crypto_kty);
    return crypto_kty;
}

jws_t crypto_advisor::sigof(crypt_sig_t sig) {
    jws_t type = jws_t::jws_unknown;
    maphint<crypt_sig_t, jws_t> hint(_sig2jws_map);

    hint.find(sig, &type);
    return type;
}

crypt_sig_t crypto_advisor::cose_sigof(cose_alg_t sig) {
    crypt_sig_t type = crypt_sig_t::sig_unknown;
    maphint<cose_alg_t, crypt_sig_t> hint(_cose2sig_map);

    hint.find(sig, &type);
    return type;
}

crypt_sig_t crypto_advisor::sigof(jws_t sig) {
    crypt_sig_t type = crypt_sig_t::sig_unknown;
    maphint<jws_t, crypt_sig_t> hint(_jws2sig_map);

    hint.find(sig, &type);
    return type;
}

cose_ec_curve_t crypto_advisor::curveof(uint32 nid) {
    cose_ec_curve_t curve = cose_ec_curve_t::cose_ec_unknown;
    maphint<uint32, cose_ec_curve_t> hint(_nid2curve_map);

    hint.find(nid, &curve);
    return curve;
}

uint32 crypto_advisor::curveof(cose_ec_curve_t curve) {
    uint32 nid = 0;
    maphint<cose_ec_curve_t, uint32> hint(_curve2nid_map);

    hint.find(curve, &nid);
    return nid;
}

}  // namespace crypto
}  // namespace hotplace
