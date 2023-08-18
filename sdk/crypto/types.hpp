/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
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

/*
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
enum crypt_symmetric_t {
    crypt_alg_unknown   = 0,
    seed                = 2,
    aes128              = 3,
    aes192              = 4,
    aes256              = 5,
    blowfish            = 7,
    idea                = 8,
    aria128             = 9,
    aria192             = 10,
    aria256             = 11,
    camellia128         = 12,
    camellia192         = 13,
    camellia256         = 14,
};

/*
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
 *    DES         : CBC, CFB, CFB1, CFB8, OFB, ECB,
 *    SEED        : CBC, CFB,             OFB, ECB,
 *    AES128      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, KEYWRAP
 *    AES192      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, KEYWRAP
 *    AES256      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, KEYWRAP
 *    BF          : CBC, CFB,             OFB, ECB
 *    IDEA        : CBC, CFB,             OFB, ECB
 *    ARIA128     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM
 *    ARIA192     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM
 *    ARIA256     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM
 *    CAMELLIA128 : CBC, CFB, CFB1, CFB8, OFB, ECB,
 *    CAMELLIA192 : CBC, CFB, CFB1, CFB8, OFB, ECB,
 *    CAMELLIA256 : CBC, CFB, CFB1, CFB8, OFB, ECB,
 */
enum crypt_mode_t {
    mode_unknown    = 0,
    cbc             = 1,
    cfb             = 2,
    cfb1            = 7,
    cfb8            = 8,
    ctr             = 4,
    ecb             = 5,
    gcm             = 6,
    ofb             = 3,
    // next         = 9

    wrap            = 20,
    pbkdf2_hmac,
};

enum hash_algorithm_t {
    /* 0 reserved */
    hash_alg_unknown    = 0,

    md4                 = 2,
    md5                 = 3,
    sha1                = 5,

    ripemd160           = 8,

    sha2_224            = 15,
    sha2_256            = 11,
    sha2_384            = 12,
    sha2_512            = 13,

    whirlpool           = 16,

    sha3_224            = 17,
    sha3_256            = 18,
    sha3_384            = 19,
    sha3_512            = 20,
    shake128            = 21,
    shake256            = 22,

    blake2b_512         = 23,
    blake2s_256         = 24,
};

enum crypt_data_type_t {
    /* binary */
    CRYPT_ITEM_AAD          = 1,    // P - protected_header.encoded, additional authenticated data
    CRYPT_ITEM_CEK          = 2,    // k - content encryption key
    CRYPT_ITEM_ENCRYPTEDKEY = 3,    // K - encrypted cek
    CRYPT_ITEM_IV           = 4,    // I - initial vector
    CRYPT_ITEM_CIPHERTEXT   = 5,    // C - ciphertext
    CRYPT_ITEM_TAG          = 6,    // T - authentication tag
    CRYPT_ITEM_APU          = 7,    // APU - agreement partyUinfo
    CRYPT_ITEM_APV          = 8,    // APV - agreement partyVinfo
    CRYPT_ITEM_P2S          = 9,    // P2S - PBES2 salt

    /* key */
    CRYPT_ITEM_RSA_N        = 64,
    CRYPT_ITEM_RSA_E        = 65,
    CRYPT_ITEM_RSA_D        = 66,
    CRYPT_ITEM_RSA_P        = 67,
    CRYPT_ITEM_RSA_Q        = 68,
    CRYPT_ITEM_RSA_DP       = 69,
    CRYPT_ITEM_RSA_DQ       = 70,
    CRYPT_ITEM_RSA_QI       = 71,

    CRYPT_ITEM_EC_CRV       = 72,
    CRYPT_ITEM_EC_X         = 73,
    CRYPT_ITEM_EC_Y         = 74,
    CRYPT_ITEM_EC_D         = 75,

    CRYPT_ITEM_HMAC_K       = 76,

    /* string */
    CRYPT_ITEM_HEADER       = 128,  // p - header (protected_header.decoded)
    CRYPT_ITEM_KID          = 129,  // kid

    /* variant */
    CRYPT_ITEM_EPK          = 256,  // ephemeral public key
    CRYPT_ITEM_P2C          = 257,  // PBES2 count
};

enum crypt_asymmetric_t {
    crypt_asymmetric_unknown    = 0,
    CRYPT_MODE_RSA_1_5          = 1,
    CRYPT_MODE_RSA_OAEP         = 2,
    CRYPT_MODE_RSA_OAEP256      = 3,
    CRYPT_MODE_EC_DH            = 4,
};


enum CRYPTO_KEY_FLAG {
    CRYPTO_KEY_PUBLIC   = (1 << 0),
    CRYPTO_KEY_PRIVATE  = (1 << 1),
};

enum CRYPTO_KEY_TYPE {
    CRYPTO_KEY_NONE         = 0,
    CRYPTO_KEY_UNSECURED    = 0,
    CRYPTO_KEY_HMAC         = 1,        // EVP_PKEY_HMAC    NID_hmac
    CRYPTO_KEY_RSA          = 2,        // EVP_PKEY_RSA     NID_rsaEncryption
    CRYPTO_KEY_EC           = 3,        // EVP_PKEY_EC      NID_X9_62_id_ecPublicKey
    CRYPTO_KEY_OKP          = 4,        // EVP_PKEY_ED25519 NID_ED25519
                                        // EVP_PKEY_ED448   NID_ED448
    CRYPTO_KEY_BAD          = 0xffff,
};
typedef CRYPTO_KEY_TYPE crypto_key_t;

enum CRYPTO_USE_FLAG {
    CRYPTO_USE_UNKNOWN  = 0,
    CRYPTO_USE_ENC      = 1,
    CRYPTO_USE_SIG      = 2,
    CRYPTO_USE_ANY      = (CRYPTO_USE_ENC | CRYPTO_USE_SIG),
};
typedef CRYPTO_USE_FLAG crypto_use_t;

enum crypt_alg_type_t {
    CRYPT_ALG_TYPE_RSA              = 1,
    CRYPT_ALG_TYPE_AESKW            = 2,
    CRYPT_ALG_TYPE_DIR              = 3,
    CRYPT_ALG_TYPE_ECDH             = 4,
    CRYPT_ALG_TYPE_ECDH_AESKW       = 5,
    CRYPT_ALG_TYPE_AESGCMKW         = 6,
    CRYPT_ALG_TYPE_PBES2_HS_AESKW   = 7,
};
#define CRYPT_AGL_VALUE(t, c) ((t << 16) | c)
#define CRYPT_ALG_TYPE(v) (v >> 16)
#define CRYPT_ALG_CODE(v) (v & 0xffff)

/*
 * @brief Cryptographic Algorithms for Key Management
 */
enum crypt_alg_t {
    CRYPT_ALG_UNKNOWN               = 0,
    CRYPT_ALG_RSA1_5                = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_RSA, 1),              // RSA1_5
    CRYPT_ALG_RSA_OAEP              = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_RSA, 2),              // RSA-OAEP
    CRYPT_ALG_RSA_OAEP_256          = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_RSA, 3),              // RSA-OAEP-256
    CRYPT_ALG_A128KW                = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_AESKW, 4),            // A128KW
    CRYPT_ALG_A192KW                = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_AESKW, 5),            // A192KW
    CRYPT_ALG_A256KW                = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_AESKW, 6),            // A256KW
    CRYPT_ALG_DIR                   = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_DIR, 7),              // dir
    CRYPT_ALG_ECDH_ES               = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_ECDH, 8),             // ECDH-ES
    CRYPT_ALG_ECDH_ES_A128KW        = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_ECDH_AESKW, 9),       // ECDH-ES+A128KW
    CRYPT_ALG_ECDH_ES_A192KW        = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_ECDH_AESKW, 10),      // ECDH-ES+A192KW
    CRYPT_ALG_ECDH_ES_A256KW        = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_ECDH_AESKW, 11),      // ECDH-ES+A256KW
    CRYPT_ALG_A128GCMKW             = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_AESGCMKW, 12),        // A128GCMKW
    CRYPT_ALG_A192GCMKW             = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_AESGCMKW, 13),        // A192GCMKW
    CRYPT_ALG_A256GCMKW             = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_AESGCMKW, 14),        // A256GCMKW
    CRYPT_ALG_PBES2_HS256_A128KW    = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_PBES2_HS_AESKW, 15),  // PBES2-HS256+A128KW
    CRYPT_ALG_PBES2_HS384_A192KW    = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_PBES2_HS_AESKW, 16),  // PBES2-HS384+A192KW
    CRYPT_ALG_PBES2_HS512_A256KW    = CRYPT_AGL_VALUE (CRYPT_ALG_TYPE_PBES2_HS_AESKW, 17),  // PBES2-HS512+A256KW
};

enum crypt_enc_type_t {
    CRYPT_ENC_TYPE_AESCBC_HS    = 1,
    CRYPT_ENC_TYPE_AESGCM       = 2,
};
#define CRYPT_ENC_VALUE(t, c) ((t << 16) | c)
#define CRYPT_ENC_TYPE(v) (v >> 16)
#define CRYPT_ENC_CODE(v) (v & 0xffff)

/*
 * @brief Cryptographic Algorithms for Content Encryption
 */
enum crypt_enc_t {
    CRYPT_ENC_UNKNOWN       = 0,
    CRYPT_ENC_A128CBC_HS256 = CRYPT_ENC_VALUE (CRYPT_ENC_TYPE_AESCBC_HS, 1),    // A128CBC-HS256
    CRYPT_ENC_A192CBC_HS384 = CRYPT_ENC_VALUE (CRYPT_ENC_TYPE_AESCBC_HS, 2),    // A192CBC-HS384
    CRYPT_ENC_A256CBC_HS512 = CRYPT_ENC_VALUE (CRYPT_ENC_TYPE_AESCBC_HS, 3),    // A256CBC-HS512
    CRYPT_ENC_A128GCM       = CRYPT_ENC_VALUE (CRYPT_ENC_TYPE_AESGCM, 4),       // A128GCM
    CRYPT_ENC_A192GCM       = CRYPT_ENC_VALUE (CRYPT_ENC_TYPE_AESGCM, 5),       // A192GCM
    CRYPT_ENC_A256GCM       = CRYPT_ENC_VALUE (CRYPT_ENC_TYPE_AESGCM, 6),       // A256GCM
};

enum crypt_sig_type_t {
    SIGN_TYPE_HMAC          = 1,    // HS256, HS384, HS512
    SIGN_TYPE_RSASSA_PKCS15 = 2,    // RS256, RS384, RS512
    SIGN_TYPE_ECDSA         = 3,    // ES256, ES384, ES512
    SIGN_TYPE_RSASSA_PSS    = 4,    // PS256, PS384, PS512
    SIGN_TYPE_EDDSA         = 5,    // EdDSA
};
#define CRYPT_SIG_VALUE(t, c) ((t << 16) | c)
#define CRYPT_SIG_TYPE(v) (v >> 16)
#define CRYPT_SIG_CODE(v) (v & 0xffff)

/*
 * @brief Cryptographic Algorithms for Digital Signatures and MACs
 * RFC 7515 JSON Web Signature (JWS)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 */
enum crypt_sig_t {
    SIGN_UNSECURED  = 0,
    SIGN_HS256      = CRYPT_SIG_VALUE (SIGN_TYPE_HMAC, 1),          // 00010001
    SIGN_HS384      = CRYPT_SIG_VALUE (SIGN_TYPE_HMAC, 2),          // 00010002
    SIGN_HS512      = CRYPT_SIG_VALUE (SIGN_TYPE_HMAC, 3),          // 00010003
    SIGN_RS256      = CRYPT_SIG_VALUE (SIGN_TYPE_RSASSA_PKCS15, 4), // 00020004
    SIGN_RS384      = CRYPT_SIG_VALUE (SIGN_TYPE_RSASSA_PKCS15, 5), // 00020005
    SIGN_RS512      = CRYPT_SIG_VALUE (SIGN_TYPE_RSASSA_PKCS15, 6), // 00020006
    SIGN_ES256      = CRYPT_SIG_VALUE (SIGN_TYPE_ECDSA, 7),         // 00030007
    SIGN_ES384      = CRYPT_SIG_VALUE (SIGN_TYPE_ECDSA, 8),         // 00030008
    SIGN_ES512      = CRYPT_SIG_VALUE (SIGN_TYPE_ECDSA, 9),         // 00030009
    SIGN_PS256      = CRYPT_SIG_VALUE (SIGN_TYPE_RSASSA_PSS, 10),   // 0004000a
    SIGN_PS384      = CRYPT_SIG_VALUE (SIGN_TYPE_RSASSA_PSS, 11),   // 0004000b
    SIGN_PS512      = CRYPT_SIG_VALUE (SIGN_TYPE_RSASSA_PSS, 12),   // 0004000c
    SIGN_EDDSA      = CRYPT_SIG_VALUE (SIGN_TYPE_EDDSA, 13),        // 0005000d
};

typedef struct _hint_blockcipher_t {
    crypt_symmetric_t _alg;
    uint16 _keysize;    // size of key
    uint16 _ivsize;     // size of initial vector
    uint16 _blocksize;  // blocksize for en/de-cryption
    uint16 _blockkw;    // blocksize for keywrap (AES)
} hint_blockcipher_t;

typedef struct _hint_jose_encryption_t {
    const char* alg_name;

    int type;                       // crypt_alg_t, crypt_enc_t
    crypto_key_t kty;               // CRYPTO_KEY_RSA, CRYPTO_KEY_EC, CRYPTO_KEY_HMAC
    crypto_key_t alt;               // for example CRYPTO_KEY_OKP, if kt is CRYPTO_KEY_EC
    int mode;                       // CRYPT_MODE_RSA_1_5, CRYPT_MODE_RSA_OAEP, CRYPT_MODE_RSA_OAEP256

    crypt_symmetric_t crypt_alg;    // algorithm for keywrap or GCM
    crypt_mode_t crypt_mode;        // crypt_mode_t::wrap, crypt_mode_t::gcm
    int keysize;                    // 16, 24, 32
    int hash_alg;

    //int ivsize;               // kw (8), gcm (12), cbc (16)
} hint_jose_encryption_t;

typedef struct _hint_curves_t {
    uint32 nid;
    uint32 kty; // crypto_key_t
    crypto_use_t use;
    const char* name;
} hint_curve_t;

typedef struct _hint_jose_signature_t {
    const char* alg_name;
    crypt_sig_t sig; // crypt_sig_t
    crypto_key_t kty;
    hash_algorithm_t alg;
    uint32 count;
    uint32 nid[5];
} hint_jose_signature_t;

typedef struct _hint_kty_name_t {
    crypto_key_t kty;
    const char* name;
} hint_kty_name_t;

typedef std::map <crypt_data_type_t, binary_t> crypt_datamap_t;
typedef std::map <crypt_data_type_t, variant_t> crypt_variantmap_t;

struct _crypt_context_t {};
typedef struct _crypt_context_t crypt_context_t;

struct _hash_context_t {};
typedef struct _hash_context_t hash_context_t;

}
}  // namespace

#endif
