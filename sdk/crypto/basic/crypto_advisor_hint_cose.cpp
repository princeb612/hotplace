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

/* keep order by group id */
const hint_cose_group_t hint_cose_groups[] = {
    {
        cose_group_sign_ecdsa,  // 1
        cose_hint_sign | cose_hint_kty_ec,
    },
    {
        cose_group_sign_eddsa,  // 2
        cose_hint_sign | cose_hint_kty_okp,
    },
    {
        cose_group_mac_hmac,  // 3
        cose_hint_mac,
    },
    {
        cose_group_mac_aes,  // 4
        cose_hint_mac,
    },
    {
        cose_group_enc_aesgcm,  // 5
        cose_hint_enc | cose_hint_iv,
    },
    {
        cose_group_enc_aesccm,  // 6
        cose_hint_enc | cose_hint_iv,
    },
    {
        cose_group_enc_chacha20_poly1305,  // 7
        cose_hint_enc | cose_hint_not_supported | cose_hint_iv,
    },
    {
        cose_group_key_direct,  // 8
        cose_hint_kty_oct,
    },
    {
        cose_group_key_hkdf_hmac,  // 9
        cose_hint_salt | cose_hint_party | cose_hint_kty_oct,
    },
    {
        cose_group_key_hkdf_aes,  // 10
        cose_hint_salt | cose_hint_party | cose_hint_kty_oct,
    },
    {
        cose_group_key_aeskw,  // 11
        cose_hint_kek | cose_hint_kty_oct,
    },
    {
        cose_group_key_ecdhes_hmac,  // 12
        cose_hint_salt | cose_hint_party | cose_hint_epk | cose_hint_kty_ec,
    },
    {
        cose_group_key_ecdhss_hmac,  // 13
        cose_hint_salt | cose_hint_party | cose_hint_static_key | cose_hint_static_kid | cose_hint_kty_ec,
    },
    {
        cose_group_key_ecdhes_aeskw,  // 14
        cose_hint_salt | cose_hint_party | cose_hint_kek | cose_hint_epk | cose_hint_kty_ec,
    },
    {
        cose_group_key_ecdhss_aeskw,  // 15
        cose_hint_salt | cose_hint_party | cose_hint_kek | cose_hint_static_key | cose_hint_static_kid | cose_hint_kty_ec,
    },
    {
        cose_group_sign_rsassa_pss,  // 16
        cose_hint_sign | cose_hint_kty_rsa,
    },
    {
        cose_group_key_rsa_oaep,  // 17
        cose_hint_kek | cose_hint_kty_rsa,
    },
    {
        cose_group_sign_rsassa_pkcs15,  // 18
        cose_hint_sign | cose_hint_kty_rsa,
    },
    {
        cose_group_iv_generate,  // 19
    },
    {
        cose_group_hash,  // 20
    },
};

const size_t sizeof_hint_cose_groups = RTL_NUMBER_OF(hint_cose_groups);

const hint_cose_algorithm_t hint_cose_algorithms[] = {
    {
        cose_alg_t::cose_aes128kw,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_aeskw - 1),
        {},
        {
            "aes-128-wrap",
            128 >> 3,  // 16
        },
    },
    {
        cose_alg_t::cose_aes192kw,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_aeskw - 1),
        {},
        {
            "aes-192-wrap",
            192 >> 3,  // 24
        },
    },
    {
        cose_alg_t::cose_aes256kw,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_aeskw - 1),
        {},
        {
            "aes-256-wrap",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_direct,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_direct,
        hint_cose_groups + (cose_group_t::cose_group_key_direct - 1),
    },
    {
        cose_alg_t::cose_es256,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
    },
    {
        cose_alg_t::cose_es384,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
    },
    {
        cose_alg_t::cose_es512,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
    },
    {
        cose_alg_t::cose_eddsa,
        crypto_kty_t::kty_okp,
        cose_group_t::cose_group_sign_eddsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_eddsa - 1),
    },
    {
        cose_alg_t::cose_hkdf_sha256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_hmac - 1),
        {
            "sha256",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_hkdf_sha512,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_hmac - 1),
        {
            "sha512",
            512 >> 3,  // 64
        },
    },
    {
        cose_alg_t::cose_hkdf_aes128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_aes,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_aes - 1),
        {
            "aes-128-cbc",
            32,
        },
    },
    {
        cose_alg_t::cose_hkdf_aes256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_aes,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_aes - 1),
        {
            "aes-256-cbc",
            64,
        },
    },
    {cose_alg_t::cose_sha1,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "sha1",
         160 >> 3,
     }},
    {cose_alg_t::cose_sha256_64,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "sha256",
         84 >> 3,
     }},
    {cose_alg_t::cose_sha256,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "sha256",
         256 >> 3,
     }},
    {cose_alg_t::cose_sha512_256,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "sha512",
         256 >> 3,
     }},
    {cose_alg_t::cose_sha384,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "sha384",
         384 >> 3,
     }},
    {cose_alg_t::cose_sha512,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "sha512",
         512 >> 3,
     }},
    {
        cose_alg_t::cose_shake128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_hash,
        hint_cose_groups + (cose_group_t::cose_group_hash - 1),
        {
            "shake128",
        },
    },
    {cose_alg_t::cose_shake256,
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {
         "shake256",
     }},
    {
        cose_alg_t::cose_ecdhes_hkdf_256,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_hmac - 1),
        {
            "sha256",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_ecdhes_hkdf_512,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_hmac - 1),
        {
            "sha512",
            512 >> 3,  // 64
        },
    },
    {
        cose_alg_t::cose_ecdhss_hkdf_256,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_hmac - 1),
        {
            "sha256",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_ecdhss_hkdf_512,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_hmac - 1),
        {
            "sha512",
            512 >> 3,  // 64
        },
    },
    {
        cose_alg_t::cose_ecdhes_a128kw,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_aeskw - 1),
        {
            "sha256",
            128 >> 3,  // 16
        },
        {
            "aes-128-wrap",
        },
    },
    {
        cose_alg_t::cose_ecdhes_a192kw,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_aeskw - 1),
        {
            "sha256",
            192 >> 3,  // 24
        },
        {
            "aes-192-wrap",
        },
    },
    {
        cose_alg_t::cose_ecdhes_a256kw,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_aeskw - 1),
        {
            "sha256",
            256 >> 3,  // 32
        },
        {
            "aes-256-wrap",
        },
    },
    {
        cose_alg_t::cose_ecdhss_a128kw,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_aeskw - 1),
        {
            "sha256",
            128 >> 3,  // 16
        },
        {
            "aes-128-wrap",
        },
    },
    {
        cose_alg_t::cose_ecdhss_a192kw,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_aeskw - 1),
        {
            "sha256",
            192 >> 3,  // 24
        },
        {
            "aes-192-wrap",
        },
    },
    {
        cose_alg_t::cose_ecdhss_a256kw,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_aeskw - 1),
        {
            "sha256",
            256 >> 3,  // 32
        },
        {
            "aes-256-wrap",
        },
    },
    {
        cose_alg_t::cose_ps256,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pss,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pss - 1),
    },
    {
        cose_alg_t::cose_ps384,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pss,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pss - 1),
    },
    {
        cose_alg_t::cose_ps512,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pss,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pss - 1),
    },
    {
        cose_alg_t::cose_rsaoaep1,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_key_rsa_oaep,
        hint_cose_groups + (cose_group_t::cose_group_key_rsa_oaep - 1),
    },
    {
        cose_alg_t::cose_rsaoaep256,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_key_rsa_oaep,
        hint_cose_groups + (cose_group_t::cose_group_key_rsa_oaep - 1),
    },
    {
        cose_alg_t::cose_rsaoaep512,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_key_rsa_oaep,
        hint_cose_groups + (cose_group_t::cose_group_key_rsa_oaep - 1),
    },
    {
        cose_alg_t::cose_es256k,
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
    },
    {
        cose_alg_t::cose_rs256,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_rs384,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_rs512,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_rs1,
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_aes128gcm,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesgcm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesgcm - 1),
        {},
        {
            "aes-128-gcm",
            128 >> 3,  // 16
            16,
        },
    },
    {
        cose_alg_t::cose_aes192gcm,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesgcm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesgcm - 1),
        {},
        {
            "aes-192-gcm",
            192 >> 3,  // 24
            16,
        },
    },
    {
        cose_alg_t::cose_aes256gcm,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesgcm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesgcm - 1),
        {},
        {
            "aes-256-gcm",
            256 >> 3,  // 32
            16,
        },
    },
    {
        cose_alg_t::cose_hs256_64,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {
            "sha256",
            64 >> 3,  // 8
            256 >> 3,
        },
    },
    {
        cose_alg_t::cose_hs256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {
            "sha256",
            256 >> 3,  // 32
            256 >> 3,
        },
    },
    {
        cose_alg_t::cose_hs384,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {
            "sha384",
            384 >> 3,  // 48
            384 >> 3,
        },
    },
    {
        cose_alg_t::cose_hs512,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {
            "sha512",
            512 >> 3,  // 64
            512 >> 3,
        },
    },
    {
        cose_alg_t::cose_aesccm_16_64_128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-128-ccm",
            128 >> 3,  // 16
            64 >> 3,   // 8
            16 >> 3,   // len(IV) = 15-2 = 13
        },
    },
    {
        cose_alg_t::cose_aesccm_16_64_256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-256-ccm",
            256 >> 3,  // 32
            64 >> 3,   // 8
            16 >> 3,   // len(IV) = 15-2 = 13
        },
    },
    {
        cose_alg_t::cose_aesccm_64_64_128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-128-ccm",
            128 >> 3,  // 16
            64 >> 3,   // 8
            64 >> 3,   // len(IV) = 15-8 = 7
        },
    },
    {
        cose_alg_t::cose_aesccm_64_64_256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-256-ccm",
            256 >> 3,  // 32
            64 >> 3,   // 8
            64 >> 3,   // len(IV) = 15-8 = 7
        },
    },
    {
        cose_alg_t::cose_aesccm_16_128_128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-128-ccm",
            128 >> 3,  // 16
            128 >> 3,  // 16
            16 >> 3,   // len(IV) = 15-2 = 13
        },
    },
    {
        cose_alg_t::cose_aesccm_16_128_256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-256-ccm",
            256 >> 3,  // 32
            128 >> 3,  // 16
            16 >> 3,   // len(IV) = 15-2 = 13
        },
    },
    {
        cose_alg_t::cose_aesccm_64_128_128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-128-ccm",
            128 >> 3,  // 16
            128 >> 3,  // 16
            64 >> 3,   // len(IV) = 15-8 = 7
        },
    },
    {
        cose_alg_t::cose_aesccm_64_128_256,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
        {
            "aes-256-ccm",
            256 >> 3,  // 32
            128 >> 3,  // 16
            64 >> 3,   // len(IV) = 15-8 = 7
        },
    },
    {
        cose_alg_t::cose_aesmac_128_64,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {
            "aes-128-cbc",
            128 >> 3,  // 16
            64 >> 3,   // 8
        },
    },
    {
        cose_alg_t::cose_aesmac_256_64,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {
            "aes-256-cbc",
            256 >> 3,  // 32
            64 >> 3,   // 8
        },
    },
    {
        cose_alg_t::cose_aesmac_128_128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {
            "aes-128-cbc",
            128 >> 3,  // 16
            128 >> 3,  // 16
        },
    },
    {
        cose_alg_t::cose_aesmac_256_128,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {
            "aes-256-cbc",
            256 >> 3,  // 32
            128 >> 3,  // 16
        },
    },
    {
        cose_alg_t::cose_chacha20_poly1305,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_chacha20_poly1305,
        hint_cose_groups + (cose_group_t::cose_group_enc_chacha20_poly1305 - 1),
        {},
        {
            "chacha20-poly1305",
            32,
            16,
        },
    },
    {
        cose_alg_t::cose_iv_generation,
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_iv_generate,
        hint_cose_groups + (cose_group_t::cose_group_iv_generate - 1),
    },
};

const size_t sizeof_hint_cose_algorithms = RTL_NUMBER_OF(hint_cose_algorithms);

}  // namespace crypto
}  // namespace hotplace
