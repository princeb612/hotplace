/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/openssl/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

#define CRYPT_CIPHER_VALUE(a, m) ((a << 16) | m)

const openssl_evp_cipher_method_t evp_cipher_methods[] = {
    /*
       EVP_des_ede_cfb
       EVP_des_ede3_cfb
       EVP_des_ede3_cfb1
       EVP_des_ede3_cfb8
       EVP_des_ede_ofb
       EVP_des_ede3_ofb
       EVP_des_cbc
       EVP_des_ede_cbc
       EVP_des_ede3_cbc
       EVP_des_ede
       EVP_des_ede3
       EVP_des_ede3_wrap

       EVP_rc4
       EVP_rc4_40
       EVP_rc4_hmac_md5

       EVP_sm4_ecb
       EVP_sm4_cbc
       EVP_sm4_cfb
       EVP_sm4_ofb
       EVP_sm4_ctr

       EVP_rc2_ecb
       EVP_rc2_cfb
       EVP_rc2_ofb
       EVP_rc2_cbc
       EVP_rc2_40_cbc
       EVP_rc2_64_cbc

       EVP_cast5_ecb
       EVP_cast5_cfb
       EVP_cast5_ofb
       EVP_cast5_cbc

       EVP_rc5_32_12_16_ecb
       EVP_rc5_32_12_16_cfb
       EVP_rc5_32_12_16_ofb
       EVP_rc5_32_12_16_cbc

       EVP_aes_128_ocb
       EVP_aes_128_xts
       EVP_aes_128_ccm
       EVP_aes_128_wrap_pad

       EVP_aes_192_ocb
       EVP_aes_192_ccm
       EVP_aes_192_wrap_pad

       EVP_aes_256_ocb
       EVP_aes_256_xts
       EVP_aes_256_ccm
       EVP_aes_256_wrap_pad

       EVP_aes_128_cbc_hmac_sha1
       EVP_aes_256_cbc_hmac_sha1
       EVP_aes_128_cbc_hmac_sha256
       EVP_aes_256_cbc_hmac_sha256

       EVP_aria_128_ccm
       EVP_aria_192_ccm
       EVP_aria_256_ccm

       EVP_chacha20
       EVP_chacha20_poly1305
     */

    { crypt_symmetric_t::seed, crypt_mode_t::cbc, EVP_seed_cbc (), "seed-cbc", },
    { crypt_symmetric_t::seed, crypt_mode_t::cfb, EVP_seed_cfb (), "seed-cfb", },
    { crypt_symmetric_t::seed, crypt_mode_t::ecb, EVP_seed_ecb (), "seed-ecb", },
    { crypt_symmetric_t::seed, crypt_mode_t::ofb, EVP_seed_ofb (), "seed-ofb", },

    { crypt_symmetric_t::aes128, crypt_mode_t::cbc,  EVP_aes_128_cbc (),  "aes-128-cbc", },
    { crypt_symmetric_t::aes128, crypt_mode_t::cfb,  EVP_aes_128_cfb (),  "aes-128-cfb", },
    { crypt_symmetric_t::aes128, crypt_mode_t::cfb1, EVP_aes_128_cfb1 (), "aes-128-cfb1", },
    { crypt_symmetric_t::aes128, crypt_mode_t::cfb8, EVP_aes_128_cfb8 (), "aes-128-cfb8", },
    { crypt_symmetric_t::aes128, crypt_mode_t::ctr,  EVP_aes_128_ctr (),  "aes-128-ctr", },
    { crypt_symmetric_t::aes128, crypt_mode_t::ecb,  EVP_aes_128_ecb (),  "aes-128-ecb", },
    { crypt_symmetric_t::aes128, crypt_mode_t::gcm,  EVP_aes_128_gcm (),  "aes-128-gcm", },
    { crypt_symmetric_t::aes128, crypt_mode_t::ofb,  EVP_aes_128_ofb (),  "aes-128-ofb", },
    { crypt_symmetric_t::aes128, crypt_mode_t::wrap, EVP_aes_128_wrap (), "aes-128-wrap", },

    { crypt_symmetric_t::aes192, crypt_mode_t::cbc,  EVP_aes_192_cbc (),  "aes-192-cbc", },
    { crypt_symmetric_t::aes192, crypt_mode_t::cfb,  EVP_aes_192_cfb (),  "aes-192-cfb", },
    { crypt_symmetric_t::aes192, crypt_mode_t::cfb1, EVP_aes_192_cfb1 (), "aes-192-cfb1", },
    { crypt_symmetric_t::aes192, crypt_mode_t::cfb8, EVP_aes_192_cfb8 (), "aes-192-cfb8", },
    { crypt_symmetric_t::aes192, crypt_mode_t::ctr,  EVP_aes_192_ctr (),  "aes-192-ctr", },
    { crypt_symmetric_t::aes192, crypt_mode_t::ecb,  EVP_aes_192_ecb (),  "aes-192-ecb", },
    { crypt_symmetric_t::aes192, crypt_mode_t::gcm,  EVP_aes_192_gcm (),  "aes-192-gcm", },
    { crypt_symmetric_t::aes192, crypt_mode_t::ofb,  EVP_aes_192_ofb (),  "aes-192-ofb", },
    { crypt_symmetric_t::aes192, crypt_mode_t::wrap, EVP_aes_192_wrap (), "aes-192-wrap", },

    { crypt_symmetric_t::aes256, crypt_mode_t::cbc,  EVP_aes_256_cbc (),  "aes-256-cbc", },
    { crypt_symmetric_t::aes256, crypt_mode_t::cfb,  EVP_aes_256_cfb (),  "aes-256-cfb", },
    { crypt_symmetric_t::aes256, crypt_mode_t::cfb1, EVP_aes_256_cfb1 (), "aes-256-cfb1", },
    { crypt_symmetric_t::aes256, crypt_mode_t::cfb8, EVP_aes_256_cfb8 (), "aes-256-cfb8", },
    { crypt_symmetric_t::aes256, crypt_mode_t::ctr,  EVP_aes_256_ctr (),  "aes-256-ctr", },
    { crypt_symmetric_t::aes256, crypt_mode_t::ecb,  EVP_aes_256_ecb (),  "aes-256-ecb", },
    { crypt_symmetric_t::aes256, crypt_mode_t::gcm,  EVP_aes_256_gcm (),  "aes-256-gcm", },
    { crypt_symmetric_t::aes256, crypt_mode_t::ofb,  EVP_aes_256_ofb (),  "aes-256-ofb", },
    { crypt_symmetric_t::aes256, crypt_mode_t::wrap, EVP_aes_256_wrap (), "aes-256-wrap", },

    { crypt_symmetric_t::blowfish, crypt_mode_t::cbc, EVP_bf_cbc (), "bf-cbc", },
    { crypt_symmetric_t::blowfish, crypt_mode_t::cfb, EVP_bf_cfb (), "bf-cfb", },
    { crypt_symmetric_t::blowfish, crypt_mode_t::ecb, EVP_bf_ecb (), "bf-ecb", },
    { crypt_symmetric_t::blowfish, crypt_mode_t::ofb, EVP_bf_ofb (), "bf-ofb", },

    { crypt_symmetric_t::idea, crypt_mode_t::cbc,  EVP_idea_cbc (),  "idea-cbc", },
    { crypt_symmetric_t::idea, crypt_mode_t::cfb,  EVP_idea_cfb (),  "idea-cfb", },
    { crypt_symmetric_t::idea, crypt_mode_t::ecb,  EVP_idea_ecb (),  "idea-ecb", },
    { crypt_symmetric_t::idea, crypt_mode_t::ofb,  EVP_idea_ofb (),  "idea-ofb", },

    { crypt_symmetric_t::aria128, crypt_mode_t::cbc,  EVP_aria_128_cbc (),  "aria-128-cbc", },
    { crypt_symmetric_t::aria128, crypt_mode_t::cfb,  EVP_aria_128_cfb (),  "aria-128-cfb", },
    { crypt_symmetric_t::aria128, crypt_mode_t::cfb1, EVP_aria_128_cfb1 (), "aria-128-cfb1", },
    { crypt_symmetric_t::aria128, crypt_mode_t::cfb8, EVP_aria_128_cfb8 (), "aria-128-cfb8", },
    { crypt_symmetric_t::aria128, crypt_mode_t::ctr,  EVP_aria_128_ctr (),  "aria-128-ctr", },
    { crypt_symmetric_t::aria128, crypt_mode_t::ecb,  EVP_aria_128_ecb (),  "aria-128-ecb", },
    { crypt_symmetric_t::aria128, crypt_mode_t::gcm,  EVP_aria_128_gcm (),  "aria-128-gcm", },
    { crypt_symmetric_t::aria128, crypt_mode_t::ofb,  EVP_aria_128_ofb (),  "aria-128-ofb", },

    { crypt_symmetric_t::aria192, crypt_mode_t::cbc,  EVP_aria_192_cbc (),  "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::cfb,  EVP_aria_192_cfb (),  "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::cfb1, EVP_aria_192_cfb1 (), "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::cfb8, EVP_aria_192_cfb8 (), "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::ctr,  EVP_aria_192_ctr (),  "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::ecb,  EVP_aria_192_ecb (),  "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::gcm,  EVP_aria_192_gcm (),  "aria-192-cbc", },
    { crypt_symmetric_t::aria192, crypt_mode_t::ofb,  EVP_aria_192_ofb (),  "aria-192-cbc", },

    { crypt_symmetric_t::aria256, crypt_mode_t::cbc,  EVP_aria_256_cbc (),  "aria-256-cbc", },
    { crypt_symmetric_t::aria256, crypt_mode_t::cfb,  EVP_aria_256_cfb (),  "aria-256-cfb", },
    { crypt_symmetric_t::aria256, crypt_mode_t::cfb1, EVP_aria_256_cfb1 (), "aria-256-cfb1", },
    { crypt_symmetric_t::aria256, crypt_mode_t::cfb8, EVP_aria_256_cfb8 (), "aria-256-cfb8", },
    { crypt_symmetric_t::aria256, crypt_mode_t::ctr,  EVP_aria_256_ctr (),  "aria-256-ctr", },
    { crypt_symmetric_t::aria256, crypt_mode_t::ecb,  EVP_aria_256_ecb (),  "aria-256-ecb", },
    { crypt_symmetric_t::aria256, crypt_mode_t::gcm,  EVP_aria_256_gcm (),  "aria-256-gcm", },
    { crypt_symmetric_t::aria256, crypt_mode_t::ofb,  EVP_aria_256_ofb (),  "aria-256-ofb", },

    { crypt_symmetric_t::camellia128, crypt_mode_t::cbc,  EVP_camellia_128_cbc (),  "camellia-128-cbc", },
    { crypt_symmetric_t::camellia128, crypt_mode_t::cfb,  EVP_camellia_128_cfb (),  "camellia-128-cfb", },
    { crypt_symmetric_t::camellia128, crypt_mode_t::cfb1, EVP_camellia_128_cfb1 (), "camellia-128-cfb1", },
    { crypt_symmetric_t::camellia128, crypt_mode_t::cfb8, EVP_camellia_128_cfb8 (), "camellia-128-cfb8", },
    { crypt_symmetric_t::camellia128, crypt_mode_t::ctr,  EVP_camellia_128_ctr (),  "camellia-128-ctr", },
    { crypt_symmetric_t::camellia128, crypt_mode_t::ecb,  EVP_camellia_128_ecb (),  "camellia-128-ecb", },
    { crypt_symmetric_t::camellia128, crypt_mode_t::ofb,  EVP_camellia_128_ofb (),  "camellia-128-ofb", },

    { crypt_symmetric_t::camellia192, crypt_mode_t::cbc,  EVP_camellia_192_cbc (),  "camellia-192-cbc", },
    { crypt_symmetric_t::camellia192, crypt_mode_t::cfb,  EVP_camellia_192_cfb (),  "camellia-192-cfb", },
    { crypt_symmetric_t::camellia192, crypt_mode_t::cfb1, EVP_camellia_192_cfb1 (), "camellia-192-cfb1", },
    { crypt_symmetric_t::camellia192, crypt_mode_t::cfb8, EVP_camellia_192_cfb8 (), "camellia-192-cfb8", },
    { crypt_symmetric_t::camellia192, crypt_mode_t::ctr,  EVP_camellia_192_ctr (),  "camellia-192-ctr", },
    { crypt_symmetric_t::camellia192, crypt_mode_t::ecb,  EVP_camellia_192_ecb (),  "camellia-192-ecb", },
    { crypt_symmetric_t::camellia192, crypt_mode_t::ofb,  EVP_camellia_192_ofb (),  "camellia-192-ofb", },

    { crypt_symmetric_t::camellia256, crypt_mode_t::cbc,  EVP_camellia_256_cbc (),  "camellia-256-cbc", },
    { crypt_symmetric_t::camellia256, crypt_mode_t::cfb,  EVP_camellia_256_cfb (),  "camellia-256-cfb", },
    { crypt_symmetric_t::camellia256, crypt_mode_t::cfb1, EVP_camellia_256_cfb1 (), "camellia-256-cfb1", },
    { crypt_symmetric_t::camellia256, crypt_mode_t::cfb8, EVP_camellia_256_cfb8 (), "camellia-256-cfb8", },
    { crypt_symmetric_t::camellia256, crypt_mode_t::ctr,  EVP_camellia_256_ctr (),  "camellia-256-ctr", },
    { crypt_symmetric_t::camellia256, crypt_mode_t::ecb,  EVP_camellia_256_ecb (),  "camellia-256-ecb", },
    { crypt_symmetric_t::camellia256, crypt_mode_t::ofb,  EVP_camellia_256_ofb (),  "camellia-256-ofb", },

};

/* something wrong EVP_CIPHER_CTX_iv_length, EVP_CIPHER_CTX_block_size (openssl-1.1.1) */
const hint_blockcipher_t hint_blockciphers [] = {
    // 16 (128), 24 (192), 32 (256)

    { crypt_symmetric_t::seed, 16, 16, 16, },

    { crypt_symmetric_t::aes128, 16, 16, 16, 16, },
    { crypt_symmetric_t::aes192, 24, 16, 16, 24, },
    { crypt_symmetric_t::aes256, 32, 16, 16, 32, },
    { crypt_symmetric_t::blowfish, 16, 8, 8, },

    { crypt_symmetric_t::idea, 16, 8, 8, },

    { crypt_symmetric_t::aria128, 16, 16, 16, },
    { crypt_symmetric_t::aria192, 24, 16, 16, },
    { crypt_symmetric_t::aria256, 32, 16, 16, },

    { crypt_symmetric_t::camellia128, 16, 16, 16, },
    { crypt_symmetric_t::camellia192, 24, 16, 16, },
    { crypt_symmetric_t::camellia256, 32, 16, 16, },
};

const openssl_evp_md_method_t evp_md_methods[] = {
    /*
       EVP_md5_sha1
       EVP_mdc2
       EVP_sha512_224
       EVP_sha512_256
     */
    { hash_algorithm_t::md4, EVP_md4 (), "md4", },
    { hash_algorithm_t::md5, EVP_md5 (), "md5", },

#if OPENSSL_VERSION_NUMBER < 10100000L
    { HASH_ALGORITHM_SHA, EVP_sha (), "sha", },
#endif
    { hash_algorithm_t::sha1, EVP_sha1 (), "sha1", },

    { hash_algorithm_t::sha2_224, EVP_sha224 (), "sha224", },
    { hash_algorithm_t::sha2_256, EVP_sha256 (), "sha256", },
    { hash_algorithm_t::sha2_384, EVP_sha384 (), "sha384", },
    { hash_algorithm_t::sha2_512, EVP_sha512 (), "sha512", },

    { hash_algorithm_t::ripemd160, EVP_ripemd160 (), "ripemd160", },

    { hash_algorithm_t::whirlpool, EVP_whirlpool (), "whirlpool", },

    { hash_algorithm_t::blake2b_512, EVP_blake2b512 (), "blake2b512", },
    { hash_algorithm_t::blake2s_256, EVP_blake2s256 (), "blake2s256", },

    { hash_algorithm_t::sha3_224, EVP_sha3_224 (), "sha3-224", },
    { hash_algorithm_t::sha3_256, EVP_sha3_256 (), "sha3-256", },
    { hash_algorithm_t::sha3_384, EVP_sha3_384 (), "sha3-384", },
    { hash_algorithm_t::sha3_512, EVP_sha3_512 (), "sha3-512", },

    { hash_algorithm_t::shake128, EVP_shake128 (), "shake128", },
    { hash_algorithm_t::shake256, EVP_shake256 (), "shake256", },

};

const hint_jose_encryption_t hint_jose_algorithms [] =
{
    { "RSA1_5",
      CRYPT_ALG_RSA1_5, CRYPTO_KEY_RSA, CRYPTO_KEY_NONE, CRYPT_MODE_RSA_1_5, },
    { "RSA-OAEP",
      CRYPT_ALG_RSA_OAEP, CRYPTO_KEY_RSA, CRYPTO_KEY_NONE, CRYPT_MODE_RSA_OAEP, },
    { "RSA-OAEP-256",
      CRYPT_ALG_RSA_OAEP_256, CRYPTO_KEY_RSA, CRYPTO_KEY_NONE, CRYPT_MODE_RSA_OAEP256, },
    { "A128KW",
      CRYPT_ALG_A128KW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes128, crypt_mode_t::wrap, 16,
      hash_algorithm_t::sha2_256, },
    { "A192KW",
      CRYPT_ALG_A192KW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes192, crypt_mode_t::wrap, 24,
      hash_algorithm_t::sha2_384, },
    { "A256KW",
      CRYPT_ALG_A256KW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes256, crypt_mode_t::wrap, 32,
      hash_algorithm_t::sha2_512, },
    { "dir",
      CRYPT_ALG_DIR, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0, },
    { "ECDH-ES",
      CRYPT_ALG_ECDH_ES, CRYPTO_KEY_EC, CRYPTO_KEY_OKP, },
    { "ECDH-ES+A128KW",
      CRYPT_ALG_ECDH_ES_A128KW, CRYPTO_KEY_EC, CRYPTO_KEY_OKP, 0,
      crypt_symmetric_t::aes128, crypt_mode_t::wrap, 16, },
    { "ECDH-ES+A192KW",
      CRYPT_ALG_ECDH_ES_A192KW, CRYPTO_KEY_EC, CRYPTO_KEY_OKP, 0,
      crypt_symmetric_t::aes192, crypt_mode_t::wrap, 24, },
    { "ECDH-ES+A256KW",
      CRYPT_ALG_ECDH_ES_A256KW, CRYPTO_KEY_EC, CRYPTO_KEY_OKP, 0,
      crypt_symmetric_t::aes256, crypt_mode_t::wrap, 32, },
    { "A128GCMKW",
      CRYPT_ALG_A128GCMKW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes128, crypt_mode_t::gcm, 16, },
    { "A192GCMKW",
      CRYPT_ALG_A192GCMKW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes192, crypt_mode_t::gcm, 24, },
    { "A256GCMKW",
      CRYPT_ALG_A256GCMKW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes256, crypt_mode_t::gcm, 32, },
    { "PBES2-HS256+A128KW",
      CRYPT_ALG_PBES2_HS256_A128KW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes128, crypt_mode_t::wrap, 16,
      hash_algorithm_t::sha2_256, },
    { "PBES2-HS384+A192KW",
      CRYPT_ALG_PBES2_HS384_A192KW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes192, crypt_mode_t::wrap, 24,
      hash_algorithm_t::sha2_384, },
    { "PBES2-HS512+A256KW",
      CRYPT_ALG_PBES2_HS512_A256KW, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes256, crypt_mode_t::wrap, 32,
      hash_algorithm_t::sha2_512, },
};

const hint_jose_encryption_t hint_jose_encryptions [] =
{
    { "A128CBC-HS256",
      CRYPT_ENC_A128CBC_HS256, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes128, crypt_mode_t::cbc, 16,
      hash_algorithm_t::sha2_256, },
    { "A192CBC-HS384",
      CRYPT_ENC_A192CBC_HS384, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes192, crypt_mode_t::cbc, 24,
      hash_algorithm_t::sha2_384, },
    { "A256CBC-HS512",
      CRYPT_ENC_A256CBC_HS512, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes256, crypt_mode_t::cbc, 32,
      hash_algorithm_t::sha2_512, },
    { "A128GCM",
      CRYPT_ENC_A128GCM, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes128, crypt_mode_t::gcm, 16, },
    { "A192GCM",
      CRYPT_ENC_A192GCM, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes192, crypt_mode_t::gcm, 24, },
    { "A256GCM",
      CRYPT_ENC_A256GCM, CRYPTO_KEY_HMAC, CRYPTO_KEY_NONE, 0,
      crypt_symmetric_t::aes256, crypt_mode_t::gcm, 32, },
};

const hint_jose_signature_t hint_jose_signatures [] = {
    { "HS256", SIGN_HS256, CRYPTO_KEY_HMAC, hash_algorithm_t::sha2_256, 1, NID_hmac, },
    { "HS384", SIGN_HS384, CRYPTO_KEY_HMAC, hash_algorithm_t::sha2_384, 1, NID_hmac, },
    { "HS512", SIGN_HS512, CRYPTO_KEY_HMAC, hash_algorithm_t::sha2_512, 1, NID_hmac, },
    { "RS256", SIGN_RS256, CRYPTO_KEY_RSA, hash_algorithm_t::sha2_256, 1, NID_rsaEncryption, },
    { "RS384", SIGN_RS384, CRYPTO_KEY_RSA, hash_algorithm_t::sha2_384, 1, NID_rsaEncryption, },
    { "RS512", SIGN_RS512, CRYPTO_KEY_RSA, hash_algorithm_t::sha2_512, 1, NID_rsaEncryption, },
    { "ES256", SIGN_ES256, CRYPTO_KEY_EC, hash_algorithm_t::sha2_256, 1, NID_X9_62_prime256v1, },
    { "ES384", SIGN_ES384, CRYPTO_KEY_EC, hash_algorithm_t::sha2_384, 1, NID_secp384r1, },
    { "ES512", SIGN_ES512, CRYPTO_KEY_EC, hash_algorithm_t::sha2_512, 1, NID_secp521r1, },
    { "PS256", SIGN_PS256, CRYPTO_KEY_RSA, hash_algorithm_t::sha2_256, 1, NID_rsaEncryption, },
    { "PS384", SIGN_PS384, CRYPTO_KEY_RSA, hash_algorithm_t::sha2_384, 1, NID_rsaEncryption, },
    { "PS512", SIGN_PS512, CRYPTO_KEY_RSA, hash_algorithm_t::sha2_512, 1, NID_rsaEncryption, },
    { "EdDSA", SIGN_EDDSA, CRYPTO_KEY_OKP, hash_algorithm_t::hash_alg_unknown, 2, NID_ED25519, NID_ED448, },
};

const hint_curve_t hint_curves [] = {
    { NID_X9_62_prime256v1, CRYPTO_KEY_EC,  CRYPTO_USE_ANY, "P-256", },
    { NID_secp384r1,        CRYPTO_KEY_EC,  CRYPTO_USE_ANY, "P-384", },
    { NID_secp521r1,        CRYPTO_KEY_EC,  CRYPTO_USE_ANY, "P-521", },
    { NID_ED25519,          CRYPTO_KEY_OKP, CRYPTO_USE_SIG, "Ed25519", },
    { NID_ED448,            CRYPTO_KEY_OKP, CRYPTO_USE_SIG, "Ed448", },
    { NID_X25519,           CRYPTO_KEY_OKP, CRYPTO_USE_ENC, "X25519", },
    { NID_X448,             CRYPTO_KEY_OKP, CRYPTO_USE_ENC, "X448", },
};

const hint_kty_name_t hint_kty_names [] = {
    { CRYPTO_KEY_HMAC,  "oct", },
    { CRYPTO_KEY_RSA,   "RSA", },
    { CRYPTO_KEY_EC,    "EC", },
    { CRYPTO_KEY_OKP,   "OKP", },
};

const size_t sizeof_hint_jose_algorithms = RTL_NUMBER_OF (hint_jose_algorithms);
const size_t sizeof_hint_jose_encryptions = RTL_NUMBER_OF (hint_jose_encryptions);
const size_t sizeof_hint_jose_signatures = RTL_NUMBER_OF (hint_jose_signatures);
const size_t sizeof_hint_curves = RTL_NUMBER_OF (hint_curves);
const size_t sizeof_hint_kty_names = RTL_NUMBER_OF (hint_kty_names);

crypto_advisor crypto_advisor::_instance;

crypto_advisor* crypto_advisor::get_instance ()
{
    return &_instance;
}

crypto_advisor::crypto_advisor () : _flag (0)
{
    build_if_necessary ();
}

return_t crypto_advisor::build_if_necessary ()
{
    return_t ret = errorcode_t::success;
    uint32 i = 0;

    if (0 == _flag) {
        _lock.enter ();
        if (0 == _flag) {
            for (i = 0; i < RTL_NUMBER_OF (hint_blockciphers); i++) {
                const hint_blockcipher_t* item = hint_blockciphers + i;
                _blockcipher_map.insert (std::make_pair (item->_alg, item));
            }
            for (i = 0; i < RTL_NUMBER_OF (evp_cipher_methods); i++) {
                const openssl_evp_cipher_method_t* item = evp_cipher_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
                EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch (nullptr, item->_fetchname, nullptr);
                _cipher_map.insert (std::make_pair (CRYPT_CIPHER_VALUE (item->_algorithm, item->_mode), evp_cipher));
#else
                _cipher_map.insert (std::make_pair (CRYPT_CIPHER_VALUE (item->_algorithm, item->_mode), item->_cipher));
#endif
                _cipher_fetch_map.insert (std::make_pair (CRYPT_CIPHER_VALUE (item->_algorithm, item->_mode), item));
                _evp_cipher_map.insert (std::make_pair (item->_cipher, item));
            }
            for (i = 0; i < RTL_NUMBER_OF (evp_md_methods); i++) {
                const openssl_evp_md_method_t* item = evp_md_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
                EVP_MD* evp_md = EVP_MD_fetch (nullptr, item->_fetchname, nullptr);
                _md_map.insert (std::make_pair (item->_algorithm, evp_md));
#else
                _md_map.insert (std::make_pair (item->_algorithm, item->_evp_md));
#endif
                _md_fetch_map.insert (std::make_pair (item->_algorithm, item));
            }
            for (i = 0; i < sizeof_hint_jose_algorithms; i++) {
                const hint_jose_encryption_t* item = hint_jose_algorithms + i;
                _alg_map.insert (std::make_pair (item->type, item));
                _alg_byname_map.insert (std::make_pair (item->alg_name, item));
            }
            for (i = 0; i < sizeof_hint_jose_encryptions; i++) {
                const hint_jose_encryption_t* item = hint_jose_encryptions + i;
                _enc_map.insert (std::make_pair (item->type, item));
                _enc_byname_map.insert (std::make_pair (item->alg_name, item));
            }
            for (i = 0; i < sizeof_hint_jose_signatures; i++) {
                const hint_jose_signature_t* item = hint_jose_signatures + i;
                _sig_map.insert (std::make_pair (item->sig, item));
                _sig_byname_map.insert (std::make_pair (item->alg_name, item));
            }
            for (i = 0; i < sizeof_hint_jose_signatures; i++) {
                const hint_jose_signature_t* item = hint_jose_signatures + i;
                for (uint midx = 0; midx < item->count; midx++) {
                    _sig_bynid_map.insert (std::make_pair (item->nid[midx], item));
                }
            }
            for (i = 0; i < sizeof_hint_curves; i++) {
                const hint_curve_t* item = hint_curves + i;
                _nid_bycurve_map.insert (std::make_pair (item->name, item));
                _curve_bynid_map.insert (std::make_pair (item->nid, item));
            }

            _flag = 1;
        }
        _lock.leave ();
    }
    return ret;
}

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher (crypt_symmetric_t alg)
{
    const hint_blockcipher_t* item = nullptr;

    _lock.enter ();
    blockcipher_map_t::iterator iter = _blockcipher_map.find (alg);

    if (_blockcipher_map.end () != iter) {
        item = iter->second;
    }

    _lock.leave ();

    return item;
}

const hint_blockcipher_t* crypto_advisor::find_evp_cipher (const EVP_CIPHER* cipher)
{
    const hint_blockcipher_t* blockcipher = nullptr;
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();

        crypt_symmetric_t alg = crypt_symmetric_t::crypt_alg_unknown;
        crypt_mode_t mode = crypt_mode_t::mode_unknown;
        ret = find_evp_cipher (cipher, alg, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        blockcipher = hintof_blockcipher (alg);
    }
    __finally2
    {
        _lock.leave ();
    }
    return blockcipher;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher (crypt_symmetric_t algorithm, crypt_mode_t mode)
{
    EVP_CIPHER* ret_value = nullptr;

    uint32 key = CRYPT_CIPHER_VALUE (algorithm, mode);

    _lock.enter ();
    cipher_map_t::iterator iter = _cipher_map.find (key);

    if (_cipher_map.end () != iter) {
        ret_value = (EVP_CIPHER*) iter->second;
    }
    _lock.leave ();

    return ret_value;
}

return_t crypto_advisor::find_evp_cipher (const EVP_CIPHER* cipher, crypt_symmetric_t& algorithm, crypt_mode_t& mode)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2
        {
            _lock.enter ();
            evp_cipher_map_t::iterator iter = _evp_cipher_map.find (cipher);

            if (_evp_cipher_map.end () == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            }

            algorithm = iter->second->_algorithm;
            mode = iter->second->_mode;
        }
        __finally2
        {
            _lock.leave ();
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

const char* crypto_advisor::nameof_cipher (crypt_symmetric_t algorithm, crypt_mode_t mode)
{
    return_t ret = errorcode_t::success;
    const char* ret_value = nullptr;

    __try2
    {
        _lock.enter ();

        cipher_fetch_map_t::iterator iter = _cipher_fetch_map.find (CRYPT_CIPHER_VALUE (algorithm, mode));
        if (_cipher_fetch_map.end () == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        const openssl_evp_cipher_method_t* item = iter->second;

        ret_value = item->_fetchname;
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md (hash_algorithm_t algorithm)
{
    const EVP_MD* ret_value = nullptr;

    _lock.enter ();
    md_map_t::iterator iter = _md_map.find (algorithm);

    if (_md_map.end () != iter) {
        ret_value = iter->second;
    }
    _lock.leave ();

    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md (crypt_sig_t sig)
{
    const EVP_MD* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_jose_signature_t* hint = advisor->hintof_jose_signature (sig);
        if (nullptr == hint) {
            __leave2;
        }
        ret_value = find_evp_md (hint->alg);
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

hash_algorithm_t crypto_advisor::get_algorithm (crypt_sig_t sig)
{
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        const hint_jose_signature_t* hint = advisor->hintof_jose_signature (sig);
        if (nullptr == hint) {
            __leave2;
        }
        ret_value = hint->alg;
    }
    __finally2
    {
        // do nothing
    }
    return ret_value;
}

const char* crypto_advisor::nameof_md (hash_algorithm_t algorithm)
{
    const char* ret_value = nullptr;
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();
        md_fetch_map_t::iterator iter = _md_fetch_map.find (algorithm);

        if (_md_fetch_map.end () == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        }


        const openssl_evp_md_method_t* item = iter->second;
        ret_value = item->_fetchname;
    }
    __finally2
    {
        _lock.leave ();
    }

    return ret_value;
}

#if __cplusplus >= 201103L    // c++11
return_t crypto_advisor::jose_for_each_algorithm (std::function <void (const hint_jose_encryption_t*, void*)> f, void* user)
{
    return_t ret = errorcode_t::success;

    std::for_each (hint_jose_algorithms,
                   hint_jose_algorithms + RTL_NUMBER_OF (hint_jose_algorithms),
                   [&] (const hint_jose_encryption_t& item) {
                return f (&item, user);
            } );
    return ret;
}

return_t crypto_advisor::jose_for_each_encryption (std::function <void (const hint_jose_encryption_t*, void*)> f, void* user)
{
    return_t ret = errorcode_t::success;

    std::for_each (hint_jose_encryptions,
                   hint_jose_encryptions + RTL_NUMBER_OF (hint_jose_encryptions),
                   [&] (const hint_jose_encryption_t& item) {
                return f (&item, user);
            } );
    return ret;
}

return_t crypto_advisor::jose_for_each_signature (std::function <void (const hint_jose_signature_t*, void*)> f, void* user)
{
    return_t ret = errorcode_t::success;

    std::for_each (hint_jose_signatures,
                   hint_jose_signatures + RTL_NUMBER_OF (hint_jose_signatures),
                   [&] (const hint_jose_signature_t& item) {
                return f (&item, user);
            } );
    return ret;
}
#endif

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm (crypt_alg_t alg)
{
    const hint_jose_encryption_t* item = nullptr;

    _lock.enter ();
    jose_encryption_map_t::iterator iter = _alg_map.find (alg);

    if (_alg_map.end () != iter) {
        item = iter->second;
    }
    _lock.leave ();

    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption (crypt_enc_t enc)
{
    const hint_jose_encryption_t* item = nullptr;

    _lock.enter ();
    jose_encryption_map_t::iterator iter = _enc_map.find (enc);

    if (_enc_map.end () != iter) {
        item = iter->second;
    }
    _lock.leave ();

    return item;
}

const hint_jose_signature_t* crypto_advisor::hintof_jose_signature (crypt_sig_t sig)
{
    const hint_jose_signature_t* item = nullptr;

    _lock.enter ();
    jose_signature_map_t::iterator iter = _sig_map.find (sig);

    if (_sig_map.end () != iter) {
        item = iter->second;
    }
    _lock.leave ();

    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve_nid (uint32 nid)
{
    const hint_curve_t* item = nullptr;

    _lock.enter ();
    jose_curve_bynid_map_t::iterator iter = _curve_bynid_map.find (nid);

    if (_curve_bynid_map.end () != iter) {
        item = iter->second;
    }
    _lock.leave ();

    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm (const char* alg)
{
    const hint_jose_encryption_t* item = nullptr;

    if (alg) {
        _lock.enter ();
        jose_encryption_byname_map_t::iterator iter = _alg_byname_map.find (alg);
        if (_alg_byname_map.end () != iter) {
            item = iter->second;
        }
        _lock.leave ();
    }

    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption (const char* enc)
{
    const hint_jose_encryption_t* item = nullptr;

    if (enc) {
        _lock.enter ();
        jose_encryption_byname_map_t::iterator iter = _enc_byname_map.find (enc);
        if (_enc_byname_map.end () != iter) {
            item = iter->second;
        }
        _lock.leave ();
    }

    return item;
}

const hint_jose_signature_t* crypto_advisor::hintof_jose_signature (const char* sig)
{
    const hint_jose_signature_t* item = nullptr;

    if (sig) {
        _lock.enter ();
        jose_signature_byname_map_t::iterator iter = _sig_byname_map.find (sig);
        if (_sig_byname_map.end () != iter) {
            item = iter->second;
        }
        _lock.leave ();
    }

    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve (const char* curve)
{
    const hint_curve_t* item = nullptr;

    if (curve) {
        _lock.enter ();
        jose_nid_bycurve_map_t::iterator iter = _nid_bycurve_map.find (curve);
        if (_nid_bycurve_map.end () != iter) {
            item = iter->second;
        }
        _lock.leave ();
    }

    return item;
}

const char* crypto_advisor::nameof_jose_algorithm (crypt_alg_t alg)
{
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_algorithm (alg);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_encryption (crypt_enc_t enc)
{
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_encryption (enc);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_signature (crypt_sig_t sig)
{
    const char* name = nullptr;

    const hint_jose_signature_t* item = hintof_jose_signature (sig);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

return_t crypto_advisor::typeof_jose_algorithm (const char* alg, crypt_alg_t& type)
{
    return_t ret = errorcode_t::success;

    type = CRYPT_ALG_UNKNOWN;
    const hint_jose_encryption_t* item = hintof_jose_algorithm (alg);

    if (item) {
        type = (crypt_alg_t) item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_encryption (const char* enc, crypt_enc_t& type)
{
    return_t ret = errorcode_t::success;

    type = CRYPT_ENC_UNKNOWN;
    const hint_jose_encryption_t* item = hintof_jose_encryption (enc);

    if (item) {
        type = (crypt_enc_t) item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_signature (const char* sig, crypt_sig_t& type)
{
    return_t ret = errorcode_t::success;

    type = SIGN_UNSECURED;
    const hint_jose_signature_t* item = hintof_jose_signature (sig);

    if (item) {
        type = (crypt_sig_t) item->sig;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::nidof_ec_curve (const char* curve, uint32& nid)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        nid = 0;

        if (nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_curve_t* item = hintof_curve (curve);
        if (item) {
            nid = item->nid;
        } else {
            ret = errorcode_t::not_found;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::ktyof_ec_curve (const char* curve, uint32& kty)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        kty = 0;

        if (nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_curve_t* item = hintof_curve (curve);
        if (item) {
            kty = item->kty;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::ktyof_ec_curve (const EVP_PKEY* pkey, std::string& kty)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        kty.clear ();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        nidof_evp_pkey (pkey, nid);
        const hint_curve_t* item = hintof_curve_nid (nid);
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
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::nameof_ec_curve (const EVP_PKEY* pkey, std::string& name)
{
    return_t ret = errorcode_t::success;
    uint32 nid = 0;

    name.clear ();

    if (kindof_ecc (pkey)) {
        nidof_evp_pkey (pkey, nid);

        _lock.enter ();
        jose_curve_bynid_map_t::iterator iter = _curve_bynid_map.find (nid);
        if (_curve_bynid_map.end () != iter) {
            name = iter->second->name;
        } else {
            ret = errorcode_t::not_found;
        }
        _lock.leave ();
    }
    return ret;
}

bool crypto_advisor::is_kindof (const EVP_PKEY* pkey, const char* alg)
{
    bool test = false;

    __try2
    {
        const hint_jose_encryption_t* hint_alg = hintof_jose_algorithm (alg);
        if (hint_alg) {
            test = is_kindof (pkey, (crypt_alg_t) hint_alg->type);
            if (test) {
                __leave2;
            }
        }
        const hint_jose_signature_t* hint_sig = hintof_jose_signature (alg);
        if (hint_sig) {
            test = is_kindof (pkey, hint_sig->sig);
            if (test) {
                __leave2;
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof (const EVP_PKEY* pkey, crypt_alg_t alg)
{
    bool test = false;

    __try2
    {
        const hint_jose_encryption_t* hint_enc = hintof_jose_algorithm (alg);
        if (nullptr == hint_enc) {
            __leave2;
        }
        crypto_key_t kty = typeof_crypto_key (pkey);
        bool cmp1 = (hint_enc->kty == kty);
        bool cmp2 = (hint_enc->alt == CRYPTO_KEY_NONE) ? true : (hint_enc->alt == kty);
        test = (cmp1 || cmp2);
    }
    __finally2
    {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof (const EVP_PKEY* pkey, crypt_sig_t sig)
{
    bool test = false;

    __try2
    {
        _lock.enter ();

        if (nullptr == pkey) {
            __leave2;
        }

        //uint32 type = EVP_PKEY_id (pkey);
        crypto_key_t kty = typeof_crypto_key (pkey);
        uint32 nid = 0;
        nidof_evp_pkey (pkey, nid);

        const hint_jose_signature_t* hint = hintof_jose_signature (sig);
        bool cond1 = (hint->sig == sig);
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
    __finally2
    {
        _lock.leave ();
    }
    return test;
}

}
}  // namespace
