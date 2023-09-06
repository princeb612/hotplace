/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_TYPES__
#define __HOTPLACE_SDK_CRYPTO_TYPES__

#include <hotplace/sdk/base.hpp>
#include <map>

namespace hotplace {
namespace crypto {

enum crypt_poweredby_t {
    openssl = 1,
};

/**
 * RFC 2144 The CAST-128 Encryption Algorithm (May 1997)
 * RFC 2612 The CAST-256 Encryption Algorithm (June 1999)
 * RFC 3217 Triple-DES and RC2 Key Wrapping (December 2001)
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 * RFC 4493 The AES-CMAC Algorithm (June 2006)
 * RFC 4772 Security Implications of Using the Data Encryption Standard (DES) (December 2006)
 * RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 * RFC 5794 A Description of the ARIA Encryption Algorithm (March 2010)
 *
 * U.S. FIPS PUB 197 (FIPS 197) Advanced Encryption Standard (November 2001)
 *
 * ISO/IEC 18033-3 Advanced Encryption Standard (May 2002)
 *
 * International Data Encryption Algorithm (1991)
 */
enum crypt_algorithm_t {
    crypt_alg_unknown   = 0,
    aes128              = 1,
    aes192              = 2,
    aes256              = 3,
    aria128             = 4,
    aria192             = 5,
    aria256             = 6,
    blowfish            = 7,
    camellia128         = 8,
    camellia192         = 9,
    camellia256         = 10,
    cast                = 11,
    des                 = 12,
    idea                = 13,
    rc2                 = 14,
    rc5                 = 15,
    seed                = 16,
    sm4                 = 17,

    // stream cipher
    rc4                 = 101,
    chacha20            = 102,
};


/**
 * modes
 *  Authenticated encryption with additional data (AEAD) modes
 *    GCM galois counter
 *    CCM counter with ciphrt block chaining message authentication code
 *    SIV synthetic initialization vector
 *  Confidentiality only modes
 *    ECB electronic codebook
 *    CBC ciphrt block chaining
 *    CFB cipher feedback
 *    OFB output feedback
 *    CTR counter
 * supports
 *    SEED        : CBC, CFB,             OFB, ECB
 *    AES128      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM, KEYWRAP
 *    AES192      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM, KEYWRAP
 *    AES256      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM, KEYWRAP
 *    ARIA128     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM
 *    ARIA192     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM
 *    ARIA256     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM
 *    BF          : CBC, CFB,             OFB, ECB
 *    CAMELLIA128 : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR  x    x
 *    CAMELLIA192 : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR  x    x
 *    CAMELLIA256 : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR  x    x
 *    DES         : CBC, CFB, CFB1, CFB8, OFB, ECB
 *    IDEA        : CBC, CFB,             OFB, ECB
 *    SM4         : CBC, CFB,             OFB, ECB
 */
enum crypt_mode_t {
    crypt_mode_unknown  = 0,
    ecb                 = 1,
    cbc                 = 2,
    cfb                 = 3,
    cfb1                = 4,
    cfb8                = 5,
    ofb                 = 6,
    ctr                 = 7,
    gcm                 = 8,
    wrap                = 9,
    ccm                 = 10,

    stream_cipher       = 11,
    stream_aead         = gcm,
};

enum hash_algorithm_t {
    hash_alg_unknown    = 0,

    md4                 = 1,
    md5                 = 2,

    sha1                = 3,

    sha2_224            = 4,
    sha2_256            = 5,
    sha2_384            = 6,
    sha2_512            = 7,

    sha3_224            = 8,
    sha3_256            = 9,
    sha3_384            = 10,
    sha3_512            = 11,

    shake128            = 12,
    shake256            = 13,

    blake2b_512         = 14,
    blake2s_256         = 15,

    ripemd160           = 16,

    whirlpool           = 17,
};

enum crypt_mode2_t {
    rsa_1_5     = 1,
    rsa_oaep    = 2,
    rsa_oaep256 = 3,
};

enum crypt_item_t {
    /* binary */
    item_aad            = 1,    // P - protected_header.encoded, additional authenticated data
    item_cek            = 2,    // k - content encryption key
    item_encryptedkey   = 3,    // K - encrypted cek
    item_iv             = 4,    // I - initial vector
    item_ciphertext     = 5,    // C - ciphertext
    item_tag            = 6,    // T - authentication tag
    item_apu            = 7,    // APU - agreement partyUinfo
    item_apv            = 8,    // APV - agreement partyVinfo
    item_p2s            = 9,    // P2S - PBES2 salt

    /* key */
    item_rsa_n          = 64,
    item_rsa_e          = 65,
    item_rsa_d          = 66,
    item_rsa_p          = 67,
    item_rsa_q          = 68,
    item_rsa_dp         = 69,
    item_rsa_dq         = 70,
    item_rsa_qi         = 71,

    item_ec_crv         = 72,
    item_ec_x           = 73,
    item_ec_y           = 74,
    item_ec_d           = 75,

    item_hmac_k         = 76,

    /* string */
    item_header         = 128,  // p - header (protected_header.decoded)
    item_kid            = 129,  // kid

    /* variant */
    item_epk            = 256,  // ephemeral public key
    item_p2c            = 257,  // PBES2 count
};

enum crypt_access_t {
    public_key  = (1 << 0),
    private_key = (1 << 1),
};

enum crypto_key_t {
    none_key    = 0,
    hmac_key    = 1,    // EVP_PKEY_HMAC    NID_hmac
    rsa_key     = 2,    // EVP_PKEY_RSA     NID_rsaEncryption
    ec_key      = 3,    // EVP_PKEY_EC      NID_X9_62_id_ecPublicKey
    okp_key     = 4,    // EVP_PKEY_ED25519 NID_ED25519, EVP_PKEY_ED448   NID_ED448
    bad_key     = 0xffff,
};

enum crypto_use_t {
    use_unknown = 0,
    use_enc     = 1,
    use_sig     = 2,
    use_any     = (use_enc | use_sig),
};

enum jwa_type_t {
    jwa_type_rsa            = 1,
    jwa_type_aeskw          = 2,
    jwa_type_dir            = 3,
    jwa_type_ecdh           = 4,
    jwa_type_ecdh_aeskw     = 5,
    jwa_type_aesgcmkw       = 6,
    jwa_type_pbes_hs_aeskw  = 7,
};
#define CRYPT_AGL_VALUE(t, c) ((t << 16) | c)
#define CRYPT_ALG_TYPE(v) (v >> 16)
#define CRYPT_ALG_CODE(v) (v & 0xffff)

/**
 * @brief Cryptographic Algorithms for Key Management
 */
enum jwa_t {
    jwa_unknown             = 0,
    jwa_rsa_1_5             = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_rsa, 1),                // RSA1_5
    jwa_rsa_oaep            = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_rsa, 2),                // RSA-OAEP
    jwa_rsa_oaep_256        = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_rsa, 3),                // RSA-OAEP-256
    jwa_a128kw              = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_aeskw, 4),              // A128KW
    jwa_a192kw              = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_aeskw, 5),              // A192KW
    jwa_a256kw              = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_aeskw, 6),              // A256KW
    jwa_dir                 = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_dir, 7),                // dir
    jwa_ecdh_es             = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_ecdh, 8),               // ECDH-ES
    jwa_ecdh_es_a128kw      = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_ecdh_aeskw, 9),         // ECDH-ES+A128KW
    jwa_ecdh_es_a192kw      = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_ecdh_aeskw, 10),        // ECDH-ES+A192KW
    jwa_ecdh_es_a256kw      = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_ecdh_aeskw, 11),        // ECDH-ES+A256KW
    jwa_a128gcmkw           = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_aesgcmkw, 12),          // A128GCMKW
    jwa_a192gcmkw           = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_aesgcmkw, 13),          // A192GCMKW
    jwa_a256gcmkw           = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_aesgcmkw, 14),          // A256GCMKW
    jwa_pbes2_hs256_a128kw  = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_pbes_hs_aeskw, 15),     // PBES2-HS256+A128KW
    jwa_pbes2_hs384_a192kw  = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_pbes_hs_aeskw, 16),     // PBES2-HS384+A192KW
    jwa_pbes2_hs512_a256kw  = CRYPT_AGL_VALUE (jwa_type_t::jwa_type_pbes_hs_aeskw, 17),     // PBES2-HS512+A256KW
};

enum jwe_type_t {
    jwe_type_aescbc_hs  = 1,
    jwe_type_aesgcm     = 2,
};
#define CRYPT_ENC_VALUE(t, c) ((t << 16) | c)
#define CRYPT_ENC_TYPE(v) (v >> 16)
#define CRYPT_ENC_CODE(v) (v & 0xffff)

/**
 * @brief Cryptographic Algorithms for Content Encryption
 */
enum jwe_t {
    jwe_unknown         = 0,
    jwe_a128cbc_hs256   = CRYPT_ENC_VALUE (jwe_type_t::jwe_type_aescbc_hs, 1),  // A128CBC-HS256
    jwe_a192cbc_hs384   = CRYPT_ENC_VALUE (jwe_type_t::jwe_type_aescbc_hs, 2),  // A192CBC-HS384
    jwe_a256cbc_hs512   = CRYPT_ENC_VALUE (jwe_type_t::jwe_type_aescbc_hs, 3),  // A256CBC-HS512
    jwe_a128gcm         = CRYPT_ENC_VALUE (jwe_type_t::jwe_type_aesgcm, 4),     // A128GCM
    jwe_a192gcm         = CRYPT_ENC_VALUE (jwe_type_t::jwe_type_aesgcm, 5),     // A192GCM
    jwe_a256gcm         = CRYPT_ENC_VALUE (jwe_type_t::jwe_type_aesgcm, 6),     // A256GCM
};

enum jws_type_t {
    jws_type_hmac           = 1,    // HS256, HS384, HS512
    jws_type_rsassa_pkcs15  = 2,    // RS256, RS384, RS512
    jws_type_ecdsa          = 3,    // ES256, ES384, ES512
    jws_type_rsassa_pss     = 4,    // PS256, PS384, PS512
    jws_type_eddsa          = 5,    // EdDSA
};
#define CRYPT_SIG_VALUE(t, c) ((t << 16) | c)
#define CRYPT_SIG_TYPE(v) (v >> 16)
#define CRYPT_SIG_CODE(v) (v & 0xffff)

/**
 * @brief Cryptographic Algorithms for Digital Signatures and MACs
 * RFC 7515 JSON Web Signature (JWS)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 */
enum jws_t {
    jws_unknown = 0,
    jws_hs256   = CRYPT_SIG_VALUE (jws_type_t::jws_type_hmac, 1),               // 00010001
    jws_hs384   = CRYPT_SIG_VALUE (jws_type_t::jws_type_hmac, 2),               // 00010002
    jws_hs512   = CRYPT_SIG_VALUE (jws_type_t::jws_type_hmac, 3),               // 00010003
    jws_rs256   = CRYPT_SIG_VALUE (jws_type_t::jws_type_rsassa_pkcs15, 4),      // 00020004
    jws_rs384   = CRYPT_SIG_VALUE (jws_type_t::jws_type_rsassa_pkcs15, 5),      // 00020005
    jws_rs512   = CRYPT_SIG_VALUE (jws_type_t::jws_type_rsassa_pkcs15, 6),      // 00020006
    jws_es256   = CRYPT_SIG_VALUE (jws_type_t::jws_type_ecdsa, 7),              // 00030007
    jws_es384   = CRYPT_SIG_VALUE (jws_type_t::jws_type_ecdsa, 8),              // 00030008
    jws_es512   = CRYPT_SIG_VALUE (jws_type_t::jws_type_ecdsa, 9),              // 00030009
    jws_ps256   = CRYPT_SIG_VALUE (jws_type_t::jws_type_rsassa_pss, 10),        // 0004000a
    jws_ps384   = CRYPT_SIG_VALUE (jws_type_t::jws_type_rsassa_pss, 11),        // 0004000b
    jws_ps512   = CRYPT_SIG_VALUE (jws_type_t::jws_type_rsassa_pss, 12),        // 0004000c
    jws_eddsa   = CRYPT_SIG_VALUE (jws_type_t::jws_type_eddsa, 13),             // 0005000d
};

typedef struct _hint_blockcipher_t {
    crypt_algorithm_t _alg;
    uint16 _keysize;    // size of key
    uint16 _ivsize;     // size of initial vector
    uint16 _blocksize;  // blocksize for en/de-cryption
    uint16 _blockkw;    // blocksize for keywrap (AES)
} hint_blockcipher_t;

typedef struct _hint_jose_encryption_t {
    const char* alg_name;

    int type;                       // jwa_t, jwe_t
    crypto_key_t kty;               // crypto_key_t::rsa_key, crypto_key_t::ec_key, crypto_key_t::hmac_key
    crypto_key_t alt;               // for example crypto_key_t::okp_key, if kt is crypto_key_t::ec_key
    int mode;                       // crypt_mode2_t::rsa_1_5, crypt_mode2_t::rsa_oaep, crypt_mode2_t::rsa_oaep256

    crypt_algorithm_t crypt_alg;    // algorithm for keywrap or GCM
    crypt_mode_t crypt_mode;        // crypt_mode_t::wrap, crypt_mode_t::gcm
    int keysize;                    // 16, 24, 32
    int hash_alg;
} hint_jose_encryption_t;

typedef struct _hint_curves_t {
    uint32 nid;
    uint32 kty; // crypto_key_t
    crypto_use_t use;
    const char* name;
} hint_curve_t;

typedef struct _hint_jose_signature_t {
    const char* alg_name;
    jws_t sig; // jws_t
    crypto_key_t kty;
    hash_algorithm_t alg;
    uint32 count;
    uint32 nid[5];
} hint_jose_signature_t;

typedef struct _hint_kty_name_t {
    crypto_key_t kty;
    const char* name;
} hint_kty_name_t;

typedef std::map <crypt_item_t, binary_t> crypt_datamap_t;
typedef std::map <crypt_item_t, variant_t> crypt_variantmap_t;

struct _crypt_context_t {};
typedef struct _crypt_context_t crypt_context_t;

struct _hash_context_t {};
typedef struct _hash_context_t hash_context_t;

struct _otp_context_t {};
typedef struct _otp_context_t otp_context_t;

}
}  // namespace

#endif
