/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/cose/cose.xhtml
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
        crypt_category_sign,
        cose_hint_sign | cose_hint_kty_ec,
    },
    {
        cose_group_sign_eddsa,  // 2
        crypt_category_sign,
        cose_hint_sign | cose_hint_kty_okp,
    },
    {
        cose_group_mac_hmac,  // 3
        crypt_category_mac,
        cose_hint_mac,
    },
    {
        cose_group_mac_aes,  // 4
        crypt_category_mac,
        cose_hint_mac,
    },
    {
        cose_group_enc_aesgcm,  // 5
        crypt_category_crypt,
        cose_hint_enc | cose_hint_iv,
    },
    {
        cose_group_enc_aesccm,  // 6
        crypt_category_crypt,
        cose_hint_enc | cose_hint_iv,
    },
    {
        cose_group_enc_chacha20_poly1305,  // 7
        crypt_category_crypt,
        cose_hint_enc | cose_hint_not_supported | cose_hint_iv,
    },
    {
        cose_group_key_direct,  // 8
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_kty_oct,
    },
    {
        cose_group_key_hkdf_hmac,  // 9
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_salt | cose_hint_party | cose_hint_kty_oct,
    },
    {
        cose_group_key_hkdf_aes,  // 10
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_salt | cose_hint_party | cose_hint_kty_oct,
    },
    {
        cose_group_key_aeskw,  // 11
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_kek | cose_hint_kty_oct,
    },
    {
        cose_group_key_ecdhes_hmac,  // 12
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_salt | cose_hint_party | cose_hint_epk | cose_hint_kty_ec,
    },
    {
        cose_group_key_ecdhss_hmac,  // 13
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_salt | cose_hint_party | cose_hint_static_key | cose_hint_static_kid | cose_hint_kty_ec,
    },
    {
        cose_group_key_ecdhes_aeskw,  // 14
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_salt | cose_hint_party | cose_hint_kek | cose_hint_epk | cose_hint_kty_ec,
    },
    {
        cose_group_key_ecdhss_aeskw,  // 15
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_salt | cose_hint_party | cose_hint_kek | cose_hint_static_key | cose_hint_static_kid | cose_hint_kty_ec,
    },
    {
        cose_group_sign_rsassa_pss,  // 16
        crypt_category_sign,
        cose_hint_sign | cose_hint_kty_rsa,
    },
    {
        cose_group_key_rsa_oaep,  // 17
        crypt_category_keydistribution,
        cose_hint_agree | cose_hint_kek | cose_hint_kty_rsa,
    },
    {
        cose_group_sign_rsassa_pkcs15,  // 18
        crypt_category_sign,
        cose_hint_sign | cose_hint_kty_rsa,
    },
    {
        cose_group_iv_generate,  // 19
        crypt_category_unknown,
    },
    {
        cose_group_hash,  // 20
        crypt_category_hash,
    },
};

const size_t sizeof_hint_cose_groups = RTL_NUMBER_OF(hint_cose_groups);

const hint_cose_algorithm_t hint_cose_algorithms[] = {
    {
        cose_alg_t::cose_aes128kw,
        "A128KW",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_aeskw - 1),
        {},
        {},
        {
            "aes-128-wrap",
            128 >> 3,  // 16
        },
    },
    {
        cose_alg_t::cose_aes192kw,
        "A192KW",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_aeskw - 1),
        {},
        {},
        {
            "aes-192-wrap",
            192 >> 3,  // 24
        },
    },
    {
        cose_alg_t::cose_aes256kw,
        "A256KW",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_aeskw - 1),
        {},
        {},
        {
            "aes-256-wrap",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_direct,
        "direct",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_direct,
        hint_cose_groups + (cose_group_t::cose_group_key_direct - 1),
    },
    {
        cose_alg_t::cose_es256,
        "ES256",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
        {
            NID_X9_62_prime256v1,
            cose_ec_curve_t::cose_ec_p256,
        },
    },
    {
        cose_alg_t::cose_es384,
        "ES384",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
        {
            NID_secp384r1,
            cose_ec_curve_t::cose_ec_p384,
        },
    },
    {
        cose_alg_t::cose_es512,
        "ES512",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
        {
            NID_secp521r1,
            cose_ec_curve_t::cose_ec_p521,
        },
    },
    {
        cose_alg_t::cose_eddsa,
        "EdDSA",
        crypto_kty_t::kty_okp,
        cose_group_t::cose_group_sign_eddsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_eddsa - 1),
        {
            NID_ED25519,
            cose_ec_curve_t::cose_ec_ed25519,
        },
    },
    {
        cose_alg_t::cose_hkdf_sha256,
        "direct+HKDF-SHA-256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_hmac - 1),
        {},
        {
            "sha256",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_hkdf_sha512,
        "direct+HKDF-SHA-512",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_hmac - 1),
        {},
        {
            "sha512",
            512 >> 3,  // 64
        },
    },
    {
        cose_alg_t::cose_hkdf_aes128,
        "direct+HKDF-AES-128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_aes,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_aes - 1),
        {},
        {
            "aes-128-cbc",
            32,
        },
    },
    {
        cose_alg_t::cose_hkdf_aes256,
        "direct+HKDF-AES-256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_key_hkdf_aes,
        hint_cose_groups + (cose_group_t::cose_group_key_hkdf_aes - 1),
        {},
        {
            "aes-256-cbc",
            64,
        },
    },
    {cose_alg_t::cose_sha1,
     "SHA-1",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "sha1",
         160 >> 3,
     }},
    {cose_alg_t::cose_sha256_64,
     "SHA-256/64",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "sha256",
         84 >> 3,
     }},
    {cose_alg_t::cose_sha256,
     "SHA-256",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "sha256",
         256 >> 3,
     }},
    {cose_alg_t::cose_sha512_256,
     "SHA-512/256",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "sha512",
         256 >> 3,
     }},
    {cose_alg_t::cose_sha384,
     "SHA-384",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "sha384",
         384 >> 3,
     }},
    {cose_alg_t::cose_sha512,
     "SHA-512",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "sha512",
         512 >> 3,
     }},
    {
        cose_alg_t::cose_shake128,
        "SHAKE128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_hash,
        hint_cose_groups + (cose_group_t::cose_group_hash - 1),
        {},
        {
            "shake128",
        },
    },
    {cose_alg_t::cose_shake256,
     "SHAKE256",
     crypto_kty_t::kty_oct,
     cose_group_t::cose_group_hash,
     hint_cose_groups + (cose_group_t::cose_group_hash - 1),
     {},
     {
         "shake256",
     }},
    {
        cose_alg_t::cose_ecdhes_hkdf_256,
        "ECDH-ES + HKDF-256",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_hmac - 1),
        {
            NID_X9_62_prime256v1,
            cose_ec_curve_t::cose_ec_p256,
        },
        {
            "sha256",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_ecdhes_hkdf_512,
        "ECDH-ES + HKDF-512",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_hmac - 1),
        {
            NID_secp521r1,
            cose_ec_curve_t::cose_ec_p521,
        },
        {
            "sha512",
            512 >> 3,  // 64
        },
    },
    {
        cose_alg_t::cose_ecdhss_hkdf_256,
        "ECDH-SS + HKDF-256",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_hmac - 1),
        {
            NID_X9_62_prime256v1,
            cose_ec_curve_t::cose_ec_p256,
        },
        {
            "sha256",
            256 >> 3,  // 32
        },
    },
    {
        cose_alg_t::cose_ecdhss_hkdf_512,
        "ECDH-SS + HKDF-512",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_hmac,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_hmac - 1),
        {
            NID_secp521r1,
            cose_ec_curve_t::cose_ec_p521,
        },
        {
            "sha512",
            512 >> 3,  // 64
        },
    },
    {
        cose_alg_t::cose_ecdhes_a128kw,
        "ECDH-ES + A128KW",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_aeskw - 1),
        {
            NID_X9_62_prime256v1,
            cose_ec_curve_t::cose_ec_p256,
        },
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
        "ECDH-ES + A192KW",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_aeskw - 1),
        {
            NID_secp384r1,
            cose_ec_curve_t::cose_ec_p384,
        },
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
        "ECDH-ES + A256KW",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhes_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhes_aeskw - 1),
        {
            NID_secp521r1,
            cose_ec_curve_t::cose_ec_p521,
        },
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
        "ECDH-SS + A128KW",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_aeskw - 1),
        {
            NID_X9_62_prime256v1,
            cose_ec_curve_t::cose_ec_p256,
        },
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
        "ECDH-SS + A192KW",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_aeskw - 1),
        {
            NID_secp384r1,
            cose_ec_curve_t::cose_ec_p384,
        },
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
        "ECDH-SS + A256KW",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_key_ecdhss_aeskw,
        hint_cose_groups + (cose_group_t::cose_group_key_ecdhss_aeskw - 1),
        {
            NID_secp521r1,
            cose_ec_curve_t::cose_ec_p521,
        },
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
        "RSA-PSS-256",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pss,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pss - 1),
    },
    {
        cose_alg_t::cose_ps384,
        "RSA-PSS-384",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pss,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pss - 1),
    },
    {
        cose_alg_t::cose_ps512,
        "RSA-PSS-512",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pss,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pss - 1),
    },
    {
        cose_alg_t::cose_rsaoaep1,
        "RSA-OAEP",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_key_rsa_oaep,
        hint_cose_groups + (cose_group_t::cose_group_key_rsa_oaep - 1),
    },
    {
        cose_alg_t::cose_rsaoaep256,
        "RSA-OAEP-256",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_key_rsa_oaep,
        hint_cose_groups + (cose_group_t::cose_group_key_rsa_oaep - 1),
    },
    {
        cose_alg_t::cose_rsaoaep512,
        "RSA-OAEP-512",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_key_rsa_oaep,
        hint_cose_groups + (cose_group_t::cose_group_key_rsa_oaep - 1),
    },
    {
        cose_alg_t::cose_es256k,
        "ES256K",
        crypto_kty_t::kty_ec,
        cose_group_t::cose_group_sign_ecdsa,
        hint_cose_groups + (cose_group_t::cose_group_sign_ecdsa - 1),
        {
            NID_secp256k1,
            cose_ec_curve_t::cose_ec_secp256k1,
        },
    },
    {
        cose_alg_t::cose_rs256,
        "RS256",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_rs384,
        "RS384",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_rs512,
        "RS512",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_rs1,
        "RS1",
        crypto_kty_t::kty_rsa,
        cose_group_t::cose_group_sign_rsassa_pkcs15,
        hint_cose_groups + (cose_group_t::cose_group_sign_rsassa_pkcs15 - 1),
    },
    {
        cose_alg_t::cose_aes128gcm,
        "A128GCM",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesgcm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesgcm - 1),
        {},
        {},
        {
            "aes-128-gcm",
            128 >> 3,  // 16
            16,
        },
    },
    {
        cose_alg_t::cose_aes192gcm,
        "A192GCM",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesgcm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesgcm - 1),
        {},
        {},
        {
            "aes-192-gcm",
            192 >> 3,  // 24
            16,
        },
    },
    {
        cose_alg_t::cose_aes256gcm,
        "A256GCM",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesgcm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesgcm - 1),
        {},
        {},
        {
            "aes-256-gcm",
            256 >> 3,  // 32
            16,
        },
    },
    {
        cose_alg_t::cose_hs256_64,
        "HS256/64",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {},
        {
            "sha256",
            64 >> 3,  // 8
            256 >> 3,
        },
    },
    {
        cose_alg_t::cose_hs256,
        "HS256/256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {},
        {
            "sha256",
            256 >> 3,  // 32
            256 >> 3,
        },
    },
    {
        cose_alg_t::cose_hs384,
        "HS384/384",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {},
        {
            "sha384",
            384 >> 3,  // 48
            384 >> 3,
        },
    },
    {
        cose_alg_t::cose_hs512,
        "HS512/512",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_hmac,
        hint_cose_groups + (cose_group_t::cose_group_mac_hmac - 1),
        {},
        {
            "sha512",
            512 >> 3,  // 64
            512 >> 3,
        },
    },
    {
        cose_alg_t::cose_aesccm_16_64_128,
        "AES-CCM-16-64-128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-16-64-256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-64-64-128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-64-64-256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-16-128-128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-16-128-256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-64-128-128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-CCM-64-128-256",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_aesccm,
        hint_cose_groups + (cose_group_t::cose_group_enc_aesccm - 1),
        {},
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
        "AES-MAC-128/64",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {},
        {
            "aes-128-cbc",
            128 >> 3,  // 16
            64 >> 3,   // 8
        },
    },
    {
        cose_alg_t::cose_aesmac_256_64,
        "AES-MAC-256/64",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {},
        {
            "aes-256-cbc",
            256 >> 3,  // 32
            64 >> 3,   // 8
        },
    },
    {
        cose_alg_t::cose_aesmac_128_128,
        "AES-MAC-128/128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {},
        {
            "aes-128-cbc",
            128 >> 3,  // 16
            128 >> 3,  // 16
        },
    },
    {
        cose_alg_t::cose_aesmac_256_128,
        "AES-MAC-256/128",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_mac_aes,
        hint_cose_groups + (cose_group_t::cose_group_mac_aes - 1),
        {},
        {},
        {
            "aes-256-cbc",
            256 >> 3,  // 32
            128 >> 3,  // 16
        },
    },
    {
        cose_alg_t::cose_chacha20_poly1305,
        "ChaCha20/Poly1305",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_enc_chacha20_poly1305,
        hint_cose_groups + (cose_group_t::cose_group_enc_chacha20_poly1305 - 1),
        {},
        {},
        {
            "chacha20-poly1305",
            32,
            16,
        },
    },
#if 0
    {
        cose_alg_t::cose_iv_generation,
        "IV-GENERATION",
        crypto_kty_t::kty_oct,
        cose_group_t::cose_group_iv_generate,
        hint_cose_groups + (cose_group_t::cose_group_iv_generate - 1),
    },
#endif
};

const size_t sizeof_hint_cose_algorithms = RTL_NUMBER_OF(hint_cose_algorithms);

}  // namespace crypto
}  // namespace hotplace
