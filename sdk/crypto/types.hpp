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
 *    AES128      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM, KEYWRAP
 *    AES192      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM, KEYWRAP
 *    AES256      : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM, KEYWRAP
 *    ARIA128     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM
 *    ARIA192     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM
 *    ARIA256     : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM, CCM
 *    BF          : CBC, CFB,             OFB, ECB
 *    CAMELLIA128 : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR
 *    CAMELLIA192 : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR
 *    CAMELLIA256 : CBC, CFB, CFB1, CFB8, OFB, ECB, CTR
 *    CAST        : CBC, CFB,             OFB, ECB
 *    DES         : CBC, CFB,             OFB, ECB
 *    IDEA        : CBC, CFB,             OFB, ECB
 *    RC2         : CBC, CFB,             OFB, ECB
 *    RC5         : CBC, CFB,             OFB, ECB
 *    SEED        : CBC, CFB,             OFB, ECB
 *    SM4         : CBC, CFB,             OFB, ECB, CTR
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

enum crypt_enc_t {
    rsa_1_5     = 1,
    rsa_oaep    = 2,
    rsa_oaep256 = 3,
    rsa_oaep384 = 4,
    rsa_oaep512 = 5,
};

#define CRYPT_SIG_VALUE(t, c) ((t << 16) | c)
#define CRYPT_SIG_TYPE(v) (v >> 16)
#define CRYPT_SIG_CODE(v) (v & 0xffff)
enum crypt_sig_type_t {
    crypt_sig_dgst          = 0,
    crypt_sig_hmac          = 1,
    crypt_sig_rsassa_pkcs15 = 2,
    crypt_sig_ecdsa         = 3,
    crypt_sig_rsassa_pss    = 4,
    crypt_sig_eddsa         = 5,
};
enum crypt_sig_t {
    sig_unknown     = 0,

    sig_hs256       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_hmac, hash_algorithm_t::sha2_256),
    sig_hs384       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_hmac, hash_algorithm_t::sha2_384),
    sig_hs512       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_hmac, hash_algorithm_t::sha2_512),

    sig_rs256       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha2_256),
    sig_rs384       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha2_384),
    sig_rs512       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha2_512),
    sig_rs1         = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pkcs15, hash_algorithm_t::sha1),

    sig_es256       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_ecdsa, hash_algorithm_t::sha2_256),  // ECDSA w/ SHA-256
    sig_es384       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_ecdsa, hash_algorithm_t::sha2_384),  // ECDSA w/ SHA-384
    sig_es512       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_ecdsa, hash_algorithm_t::sha2_512),  // ECDSA w/ SHA-512
    sig_es256k      = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_ecdsa, hash_algorithm_t::sha2_256),  // ECDSA using secp256k1 curve and SHA-256

    sig_ps256       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pss, hash_algorithm_t::sha2_256),
    sig_ps384       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pss, hash_algorithm_t::sha2_384),
    sig_ps512       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_rsassa_pss, hash_algorithm_t::sha2_512),

    sig_eddsa       = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_eddsa, 0),

    sig_sha1        = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_dgst, hash_algorithm_t::sha1),
    sig_sha256      = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_dgst, hash_algorithm_t::sha2_256),
    sig_sha384      = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_dgst, hash_algorithm_t::sha2_384),
    sig_sha512      = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_dgst, hash_algorithm_t::sha2_512),
    sig_shake128    = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_dgst, hash_algorithm_t::shake128),
    sig_shake256    = CRYPT_SIG_VALUE (crypt_sig_type_t::crypt_sig_dgst, hash_algorithm_t::shake256),
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
    item_zip            = 130,  // zip "DEF"

    /* variant */
    item_epk            = 256,  // ephemeral public key
    item_p2c            = 257,  // PBES2 count
};

enum crypt_access_t {
    public_key  = (1 << 0),
    private_key = (1 << 1),
};

enum crypto_key_t {
    kty_unknown = 0,
    kty_hmac    = 1,    // EVP_PKEY_HMAC    NID_hmac
    kty_rsa     = 2,    // EVP_PKEY_RSA     NID_rsaEncryption
    kty_ec      = 3,    // EVP_PKEY_EC      NID_X9_62_id_ecPublicKey
    kty_okp     = 4,    // EVP_PKEY_ED25519 NID_ED25519, EVP_PKEY_ED448   NID_ED448
    kty_bad     = 0xffff,
};

/**
 * @desc    JOSE "use", COSE key operation
 *          JOSE use - enc, sig
 *          COSE keyop - sign, verify, ...
 */
enum crypto_use_t {
    use_unknown     = 0,

    // JOSE
    use_enc         = 1 << 0,
    use_sig         = 1 << 1,

    // COSE
    use_sign        = 1 << 2,
    use_verify      = 1 << 3,
    use_encrypt     = 1 << 4,
    use_decrypt     = 1 << 5,
    use_wrap        = 1 << 6,
    use_unwrap      = 1 << 7,
    use_derive_key  = 1 << 8,
    use_derive_bits = 1 << 9,
    use_mac_create  = 1 << 10,
    use_mac_verify  = 1 << 11,
    use_any         = (0xffff),
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

enum cose_header_t {
    // RFC 8152 Table 2: Common Header Parameters
    // RFC 8152 Table 3: Common Header Parameters
    cose_header_alg             = 1,    // int / tstr
    cose_header_crit            = 2,    // [+ label]
    cose_header_content_type    = 3,    // tstr / uint
    cose_header_kid             = 4,    // bstr
    cose_header_iv              = 5,    // bstr
    cose_header_partial_iv      = 6,    // bstr

    cose_header_counter_sig     = 7,    // COSE_Signature / [+ COSE_Signature]

    // RFC 8152 Table 27: Header Parameter for CounterSignature0
    cose_header_counter_sig0    = 9,

    // RFC 9338 Table 1: Common Header Parameters
    // RFC 9338 Table 2: New Common Header Parameters
    cose_header_counter_sig_v2  = 11,
    cose_header_counter_sig0_v2 = 12,

    // RFC 9360 Table 1: X.509 COSE Header Parameters
    cose_header_x5bag           = 32,
    cose_header_x5chain         = 33,
    cose_header_x5t             = 34,
    cose_header_x5u             = 35,
};
enum cose_key_lable_t {
    // RFC 8152 Table 3: Key Map Labels
    // RFC 8152 Table 4: Key Map Labels
    cose_lable_kty      = 1,
    cose_lable_kid      = 2,
    cose_lable_alg      = 3,
    cose_lable_keyops   = 4,
    cose_lable_base_iv  = 5,

    // RFC 8152 Table 23: EC Key Parameters
    // RFC 9053 Table 19: EC Key Parameters
    // cose_kty_t::cose_kty_ec2
    cose_ec_crv = -1,
    cose_ec_x   = -2,
    cose_ec_y   = -3,
    cose_ec_d   = -4,

    // RFC 8152 Table 24: Octet Key Pair Parameters
    // RFC 9053 Table 20: Octet Key Pair Parameters
    // cose_kty_t::cose_kty_okp
    cose_okp_crv    = -1,
    cose_okp_x      = -2,
    cose_okp_d      = -4,

    // RFC 8152 Table 25: Symmetric Key Parameters
    // RFC 9053 Table 21: Symmetric Key Parameters
    cose_symm_k     = -1,

    // RSA 8230 Table 4: RSA Key Parameters
    cose_rsa_n      = -1,
    cose_rsa_e      = -2,
    cose_rsa_d      = -3,
    cose_rsa_p      = -4,
    cose_rsa_q      = -5,
    cose_rsa_dp     = -6,
    cose_rsa_dq     = -7,
    cose_rsa_qi     = -8,
    cose_rsa_other  = -9,
    cose_rsa_ri     = -10,
    cose_rsa_di     = -11,
    cose_rsa_ti     = -12,
};
enum cose_alg_param_t {
    // RFC 8152 Table 19: ECDH Algorithm Parameters
    // RFC 9053 Table 15: ECDH Algorithm Parameters
    cose_ephemeral_key  = -1,
    cose_static_key     = -2,
    cose_static_key_id  = -3,

    // RFC 8152 Table 13: HKDF Algorithm Parameters
    // RFC 9053 Table 9: HKDF Algorithm Parameters
    cose_salt           = -20,

    // RFC 8152 Table 14: Context Algorithm Parameters
    // RFC 9053 Table 10: Context Algorithm Parameters
    cose_partyu_id      = -21,
    cose_partyu_nonce   = -22,
    cose_partyu_other   = -23,
    cose_partyv_id      = -24,
    cose_partyv_nonce   = -25,
    cose_partyv_other   = -26,

    // RFC 9360 Table 2: Static ECDH Algorithm Values
    cose_x5t_sender     = -27,
    cose_x5u_sender     = -28,
    cose_x5chain_sender = -29,
};

enum cose_kty_t {
    // RFC 8152 Table 21: Key Type Values
    // RFC 9053 Table 17: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    cose_kty_unknown    = 0,
    cose_kty_okp        = 1,
    cose_kty_ec2        = 2,
    cose_kty_symm       = 4,

    // RFC 8230 Table 3: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    cose_kty_rsa        = 3,

    // RFC 9053 Table 22: Key Type Capabilities
    cose_kty_hss_lms    = 5,
    cose_kty_walnutdsa  = 6,
};
enum cose_keyop_t {
    // RFC 8152 Table 4: Key Operation Values
    // RFC 8152 Table 5: Key Operation Values
    cose_keyop_sign         = 1,
    cose_keyop_verify       = 2,
    cose_keyop_encrypt      = 3,
    cose_keyop_decrypt      = 4,
    cose_keyop_wrap         = 5,
    cose_keyop_unwrap       = 6,
    cose_keyop_derive_key   = 7,
    cose_keyop_derive_bits  = 8,
    cose_keyop_mac_create   = 9,
    cose_keyop_mac_verify   = 10,
};
enum cose_ec_curve_t {
    cose_ec_unknown = 0,
    // RFC 8152 Table 22: Elliptic Curves
    // RFC 9053 Table 18: Elliptic Curves
    cose_ec_p256    = 1,
    cose_ec_p384    = 2,
    cose_ec_p521    = 3,
    cose_ec_x25519  = 4,
    cose_ec_x448    = 5,
    cose_ec_ed25519 = 6,
    cose_ec_ed448   = 7,
};
enum cose_alg_t {
    cose_unknown                = 0,

    // RFC 8152 Table 17: AES Key Wrap Algorithm Values
    // RFC 9053 Table 13: AES Key Wrap Algorithm Values
    cose_a128kw                 = -3,
    cose_a192kw                 = -4,
    cose_a256kw                 = -5,

    // RFC 8152 Table 15: Direct Key
    // RFC 9053 Table 11: Direct Key
    cose_direct                 = -6,

    // RFC 8152 Table 5: ECDSA Algorithm Values
    // RFC 9053 Table 1: ECDSA Algorithm Values
    cose_es256                  = -7,   // ECDSA w/ SHA-256
    cose_es384                  = -35,  // ECDSA w/ SHA-384
    cose_es512                  = -36,  // ECDSA w/ SHA-512

    // RFC 8152 Table 6: EdDSA Algorithm Values
    // RFC 9053 Table 2: EdDSA Algorithm Value
    cose_eddsa                  = -8,

    // RFC 8152 Table 16: Direct Key with KDF
    // RFC 9053 Table 12: Direct Key with KDF
    cose_direct_hkdf_sha_256    = -10,
    cose_direct_hkdf_sha_512    = -11,
    cose_direct_hkdf_aes_128    = -12,
    cose_direct_hkdf_aes_256    = -13,

    // RFC 9054 Table 1: SHA-1 Hash Algorithm
    cose_sha1                   = -14,

    // RFC 9054 Table 2: SHA-2 Hash Algorithms
    cose_sha256_64              = -15,
    cose_sha256                 = -16,
    cose_sha512_256             = -17,
    cose_sha384                 = -43,
    cose_sha512                 = -44,

    // RFC 9054 Table 3: SHAKE Hash Functions
    cose_shake128               = -18,
    cose_shake256               = -45,

    // RFC 8152 Table 18: ECDH Algorithm Values
    // RFC 9053 Table 14: ECDH Algorithm Values
    cose_ecdh_es_hkdf_256       = -25,
    cose_ecdh_es_hkdf_512       = -26,
    cose_ecdh_ss_hkdf_256       = -27,
    cose_ecdh_ss_hkdf_512       = -28,

    // RFC 8152 Table 20: ECDH Algorithm Values with Key Wrap
    // RFC 9053 Table 16: ECDH Algorithm Values with Key Wrap
    cose_ecdh_es_a128kw         = -29,
    cose_ecdh_es_a192kw         = -30,
    cose_ecdh_es_a256kw         = -31,
    cose_ecdh_ss_a128kw         = -32,
    cose_ecdh_ss_a192kw         = -33,
    cose_ecdh_ss_a256kw         = -34,

    // RFC 8230 Table 1: RSASSA-PSS Algorithm Values
    cose_ps256                  = -37,
    cose_ps384                  = -38,
    cose_ps512                  = -39,

    // RFC 8230 Table 2: RSAES-OAEP Algorithm Values
    cose_rsaes_oaep_sha1        = -40,
    cose_rsaes_oaep_sha256      = -41,
    cose_rsaes_oaep_sha512      = -42,

    // RFC 8812 Table 2: ECDSA Algorithm Values
    cose_es256k                 = -47,

    // RFC 8812 Table 1: RSASSA-PKCS1-v1_5 Algorithm Values
    cose_rs256                  = -257,
    cose_rs384                  = -258,
    cose_rs512                  = -259,
    cose_rs1                    = -65535,

    // RFC 8152 Table 9: Algorithm Value for AES-GCM
    // RFC 9053 Table 5: Algorithm Values for AES-GCM
    cose_aes_128_gcm            = 1,
    cose_aes_192_gcm            = 2,
    cose_aes_256_gcm            = 3,

    // RFC 8152 Table 7: HMAC Algorithm Values
    // RFC 9053 Table 3: HMAC Algorithm Values
    cose_hs256_64               = 4,    // HMAC w/ SHA-256 truncated to 64 bits, When truncating, the leftmost tag length bits are kept and transmitted.
    cose_hs256                  = 5,    // HMAC w/ SHA-256
    cose_hs384                  = 6,    // HMAC w/ SHA-384
    cose_hs512                  = 7,    // HMAC w/ SHA-512

    // RFC 8152 Table 10: Algorithm Values for AES-CCM
    // RFC 9053 Table 6: Algorithm Values for AES-CCM
    cose_aes_ccm_16_64_128      = 10,
    cose_aes_ccm_16_64_256      = 11,
    cose_aes_ccm_64_64_128      = 12,
    cose_aes_ccm_64_64_256      = 13,
    cose_aes_ccm_16_128_128     = 30,
    cose_aes_ccm_16_128_256     = 31,
    cose_aes_ccm_64_128_128     = 32,
    cose_aes_ccm_64_128_256     = 33,

    // RFC 8152 Table 8: AES-MAC Algorithm Values
    // RFC 9053 Table 4: AES-MAC Algorithm Values
    cose_aes_cbc_mac_128_64     = 14,   // AES-MAC 128-bit key, 64-bit tag
    cose_aes_cbc_mac_256_64     = 15,   // AES-MAC 256-bit key, 64-bit tag
    cose_aes_cbc_mac_128_128    = 25,   // AES-MAC 128-bit key, 128-bit tag
    cose_aes_cbc_mac_256_128    = 26,   // AES-MAC 256-bit key, 128-bit tag

    // RFC 8152 Table 11: Algorithm Value for AES-GCM
    // RFC 9053 Table 7: Algorithm Value for ChaCha20/Poly1305
    cose_chacha20_poly1305      = 24,

    // RFC 9053 Table 23: New entry in the COSE Algorithms registry
    cose_iv_generation          = 34,
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
    crypto_key_t kty;               // crypto_key_t::kty_rsa, crypto_key_t::kty_ec, crypto_key_t::kty_hmac
    crypto_key_t alt;               // for example crypto_key_t::kty_okp, if kt is crypto_key_t::kty_ec
    int mode;                       // crypt_enc_t::rsa_1_5, crypt_enc_t::rsa_oaep, crypt_enc_t::rsa_oaep256

    crypt_algorithm_t crypt_alg;    // algorithm for keywrap or GCM
    crypt_mode_t crypt_mode;        // crypt_mode_t::wrap, crypt_mode_t::gcm
    int keysize;                    // 16, 24, 32
    int hash_alg;
} hint_jose_encryption_t;

typedef struct _hint_curves_t {
    uint32 nid;
    cose_ec_curve_t cose_crv;
    crypto_key_t kty;
    crypto_use_t use;
    const char* name;           // NIST CURVE
    const char* nameof_x9_62;   // X9.62, X9.63
    const char* nameof_sec;     // Standards for Efficient Cryptography (SEC)
} hint_curve_t;

typedef struct _hint_signature_t {
    crypt_sig_t sig_type;
    jws_t jws_type;
    crypto_key_t kty;
    const char* jws_name;
    hash_algorithm_t alg;
    uint32 count;
    uint32 nid[5];
} hint_signature_t;

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
