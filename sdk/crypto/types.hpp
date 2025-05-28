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

#include <list>
#include <map>
#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/base64.hpp>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/system/endian.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

///////////////////////////////////////////////////////////////////////////
// crypt
///////////////////////////////////////////////////////////////////////////
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
    crypt_alg_unknown = 0,
    aes128 = 1,
    aes192 = 2,
    aes256 = 3,
    aria128 = 4,
    aria192 = 5,
    aria256 = 6,
    blowfish = 7,
    camellia128 = 8,
    camellia192 = 9,
    camellia256 = 10,
    cast = 11,
    des = 12,
    idea = 13,
    rc2 = 14,
    rc5 = 15,
    seed = 16,
    sm4 = 17,

    // stream cipher
    rc4 = 101,
    chacha20 = 102,
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
 *
 *  crypt_mode_t::ccm8
 *      openssl provide "aes-128-ccm", ... (not provice "aes-128-ccm8", ...)
 *      see EVP_CTRL_AEAD_SET_TAG
 *  sample
 *      auto cipher = EVP_CIPHER_fetch(nullptr, "aes-128-ccm", nullptr);
 *      EVP_CIPHER_CTX_init(context);
 *      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 8, nullptr);
 */
enum crypt_mode_t {
    mode_unknown = 0,
    ecb = 1,
    cbc = 2,
    cfb = 3,
    cfb1 = 4,
    cfb8 = 5,
    ofb = 6,
    ctr = 7,
    gcm = 8,
    wrap = 9,
    ccm = 10,    // 14-octet authentication tag
    ccm8 = 13,   // 8-octet authentication
    ccm16 = 14,  // 16-octet authentication [TLS]

    mode_cipher = 11,
    mode_chacha20 = mode_cipher,
    mode_aead = 12,
    mode_poly1305 = mode_aead,
};

enum crypt_enc_t {
    crypt_enc_undefined = 0,
    rsa_1_5 = 1,
    rsa_oaep = 2,
    rsa_oaep256 = 3,
    rsa_oaep384 = 4,
    rsa_oaep512 = 5,

    /* Integrated Encryption Scheme (IES) - not supported yet */
    ecies = 6,  // Elliptic Curve Integrated Encryption Scheme
    dlies = 7,  // Discrete Logarithm Integrated Encryption Scheme

    dhies = 8,  // DHIES
};

///////////////////////////////////////////////////////////////////////////
// digest
///////////////////////////////////////////////////////////////////////////
enum hash_algorithm_t {
    hash_alg_unknown = 0,

    md4 = 1,
    md5 = 2,

    sha1 = 3,

    sha2_224 = 4,
    sha2_256 = 5,
    sha2_384 = 6,
    sha2_512 = 7,

    sha3_224 = 8,
    sha3_256 = 9,
    sha3_384 = 10,
    sha3_512 = 11,

    shake128 = 12,
    shake256 = 13,

    blake2b_512 = 14,
    blake2s_256 = 15,

    ripemd160 = 16,

    whirlpool = 17,

    sha2_512_224 = 18,
    sha2_512_256 = 19,
};

///////////////////////////////////////////////////////////////////////////
// sign
///////////////////////////////////////////////////////////////////////////
enum crypt_sig_type_t : uint8 {
    crypt_sig_unknown = 255,
    crypt_sig_dgst = 0,           //
    crypt_sig_hmac = 1,           // HMAC (kty_oct)
    crypt_sig_rsassa_pkcs15 = 2,  // PKCS#1 Ver1.5 (kty_rsa)
    crypt_sig_ecdsa = 3,          // Elliptic Curve Digital Signature Algorithm (ECDSA)
    crypt_sig_rsassa_pss = 4,     // PKCS#1 RSASSA-PSS (kty_rsa, kty_rsapss)
    crypt_sig_eddsa = 5,          // Edwards-Curve Digital Signature Algorithms (EdDSAs)
    crypt_sig_dsa = 6,            // DSA
    crypt_sig_rsassa_x931 = 7,    // FIPS186-3, X9.31
};

enum crypt_sig_t : uint16 {
    sig_unknown = 0,

    sig_hs256 = 1,
    sig_hs384 = 2,
    sig_hs512 = 3,

    sig_rs256 = 4,
    sig_rs384 = 5,
    sig_rs512 = 6,
    sig_rs1 = 7,

    sig_es256 = 9,
    sig_es384 = 10,
    sig_es512 = 11,

    sig_ps256 = 12,
    sig_ps384 = 13,
    sig_ps512 = 14,

    sig_eddsa = 15,

    sig_sha1 = 16,
    sig_sha224 = 23,
    sig_sha256 = 17,
    sig_sha384 = 18,
    sig_sha512 = 19,
    sig_shake128 = 20,
    sig_shake256 = 21,

    sig_es256k = 22,
};

///////////////////////////////////////////////////////////////////////////
// curve
///////////////////////////////////////////////////////////////////////////
/**
 * @brief   Elliptic Curve (use openssl nid definition for convenience)
 * @sa      crypto_key
 */
enum ec_curve_t : uint32 {
    ec_p192 = 409,       // P-192, NID_X9_62_prime192v1
    ec_p224 = 713,       // P-224, NID_secp224r1
    ec_p256 = 415,       // P-256, NID_X9_62_prime256v1
    ec_p384 = 715,       // P-384, NID_secp384r1
    ec_p521 = 716,       // P-521, NID_secp521r1
    ec_k163 = 721,       // K-163, NID_sect163k1
    ec_k233 = 726,       // K-233, NID_sect233k1
    ec_k283 = 729,       // K-283, NID_sect283k1
    ec_k409 = 731,       // K-409, NID_sect409k1
    ec_k571 = 733,       // K-571, NID_sect571k1
    ec_b163 = 723,       // B-163, NID_sect163r2
    ec_b233 = 727,       // B-233, NID_sect233r1
    ec_b283 = 730,       // B-283, NID_sect283r1
    ec_b409 = 732,       // B-409, NID_sect409r1
    ec_b571 = 734,       // B-571, NID_sect571r1
    ec_secp160r1 = 709,  // secp160r1, NID_secp160r1
    ec_x25519 = 1034,    // X25519, NID_X25519
    ec_x448 = 1035,      // X448, NID_X448
    ec_ed25519 = 1087,   // Ed25519, NID_Ed25519
    ec_ed448 = 1088,     // Ed448, NID_Ed448
    ec_p256k = 714,      // NID_secp256k1

    ec_secp160k1 = 708,  // NID_secp160k1
    ec_secp160r2 = 710,  // NID_secp160r2
    ec_secp192k1 = 711,  // NID_secp192k1
    ec_secp224k1 = 712,  // NID_secp224k1
    ec_secp224r1 = 713,  // NID_secp224r1
    ec_secp256k1 = 714,  // NID_secp256k1
    ec_sect163r1 = 722,  // NID_sect163r1
    ec_sect193r1 = 724,  // NID_sect193r1
    ec_sect193r2 = 725,  // NID_sect193r2
    ec_sect239k1 = 728,  // NID_sect239k1

    ec_brainpoolP256r1 = 927,  // brainpoolP256r1, NID_brainpoolP256r1
    ec_brainpoolP256t1 = 928,  // brainpoolP256t1, NID_brainpoolP256t1
    ec_brainpoolP320r1 = 929,  // brainpoolP320r1, NID_brainpoolP320r1
    ec_brainpoolP320t1 = 930,  // brainpoolP320t1, NID_brainpoolP320t1
    ec_brainpoolP384r1 = 931,  // brainpoolP384r1, NID_brainpoolP384r1
    ec_brainpoolP384t1 = 932,  // brainpoolP384t1, NID_brainpoolP384t1
    ec_brainpoolP512r1 = 933,  // brainpoolP512r1, NID_brainpoolP512r1
    ec_brainpoolP512t1 = 934,  // brainpoolP512t1, NID_brainpoolP512t1
};

///////////////////////////////////////////////////////////////////////////
// key
///////////////////////////////////////////////////////////////////////////
/**
 * @brief get key
 * @sa crypto_key::get_key
 * @remarks
 * if there are both public_key | asn1public_key in the flag, asn1public_key has higher priority.
 * | key type   | public_key               | asn1public_key | private_key  |
 * | kty_oct    | N/A                      | N/A            | item_hmac_k  |
 * | kty_okp    | item_ec_x                | item_asn1der   | item_ec_d    |
 * | kty_ec     | item_ec_pub_uncompressed | item_asn1der   | item_ec_d    |
 * | kty_rsa    | N/A                      | item_asn1der   | item_rsa_d   |
 * | kty_rsapss | N/A                      | item_asn1der   | item_rsa_d   |
 * | kty_dh     | item_dh_pub              | item_asn1der   | item_dh_priv |
 * | kty_dsa    | N/A                      | item_asn1der   | item_dsa_x   |
 */
enum crypt_access_t {
    public_key = (1 << 0),      // simple and common representation
    private_key = (1 << 1),     //
    asn1public_key = (1 << 2),  // ASN.1 DER representation
};

enum crypto_kty_t : uint16 {
    kty_unknown = 0,
    kty_hmac = 1,        // NID_hmac
    kty_oct = kty_hmac,  // NID_hmac (synomym)
    kty_rsa = 2,         // NID_rsaEncryption, NID_rsa
    kty_ec = 3,          // NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1
    kty_okp = 4,         // NID_X25519, NID_X448, NID_ED25519, NID_ED448
    kty_dh = 5,          // NID_dhKeyAgreement
    kty_rsapss = 6,      // NID_rsassaPss
    kty_dsa = 7,         // NID_dsa
    kty_bad = 0xffff,
};

/**
 * @desc    JOSE "use", COSE key operation
 *          JOSE use - enc, sig
 *          COSE keyop - sign, verify, ...
 */
enum crypto_use_t : uint16 {
    use_unknown = 0,

    // JOSE
    use_enc = 1 << 0,
    use_sig = 1 << 1,

    // COSE
    use_sign = 1 << 2,
    use_verify = 1 << 3,
    use_encrypt = 1 << 4,
    use_decrypt = 1 << 5,
    use_wrap = 1 << 6,
    use_unwrap = 1 << 7,
    use_derive_key = 1 << 8,
    use_derive_bits = 1 << 9,
    use_mac_create = 1 << 10,
    use_mac_verify = 1 << 11,
    use_any = (0xffff),
};

enum crypt_item_t : uint16 {
    /* binary */
    item_aad = 1,           // P - protected_header.encoded, additional authenticated data
    item_cek = 2,           // k - content encryption key
    item_encryptedkey = 3,  // K - encrypted cek
    item_iv = 4,            // I - initial vector
    item_ciphertext = 5,    // C - ciphertext
    item_tag = 6,           // T - authentication tag
    item_apu = 7,           // APU - agreement partyUinfo
    item_apv = 8,           // APV - agreement partyVinfo
    item_p2s = 9,           // P2S - PBES2 salt

    item_asn1der = 63,
    item_rsa_pub = item_asn1der,
    item_rsa_n = 64,
    item_rsa_e = 65,
    item_rsa_d = 66,
    item_rsa_priv = item_rsa_d,
    item_rsa_p = 67,
    item_rsa_q = 68,
    item_rsa_dp = 69,
    item_rsa_dq = 70,
    item_rsa_qi = 71,

    item_ec_crv = 72,
    item_ec_x = 73,
    item_ec_y = 74,
    item_ec_d = 75,

    item_hmac_k = 76,

    item_ec_pub_uncompressed = 77,
    item_ec_pub = item_ec_pub_uncompressed,

    item_dh_pub = 78,
    item_dh_priv = 79,

    /**
     * DSA
     *   public key
     *     p (prime)
     *     q (subprime)
     *     g (generator)
     *     y (public key)
     *   private key
     *     x (private key)
     *   signature
     *     k (nonce)
     *     r (signature 1)
     *     s (signature 2)
     */
    item_dsa_pub = item_asn1der,
    item_dsa_priv = 80,
    item_dsa_p = 81,
    item_dsa_q = 82,
    item_dsa_g = 83,
    item_dsa_y = 84,
    item_dsa_x = item_dsa_priv,

    /* string */
    item_header = 128,  // p - header (protected_header.decoded)
    item_kid = 129,     // kid
    item_zip = 130,     // zip "DEF"

    /* variant */
    item_epk = 256,  // ephemeral public key (pointer to EVP_PKEY*)
    item_p2c = 257,  // PBES2 count (int32)
};

///////////////////////////////////////////////////////////////////////////
// TLS
///////////////////////////////////////////////////////////////////////////

// TLS key exchange
enum keyexchange_t {
    keyexchange_null = 0,
    keyexchange_rsa = 1,           // Rivest Shamir Adleman algorithm (RSA)
    keyexchange_dh = 2,            // Diffie-Hellman (DH)
    keyexchange_dhe = 3,           // Diffie-Hellman Ephemeral (DHE)
    keyexchange_krb5 = 4,          // Kerberos 5 (KRB5)
    keyexchange_psk = 5,           // Pre-Shared Key (PSK)
    keyexchange_ecdh = 6,          // Elliptic Curve Diffie-Hellman (ECDH)
    keyexchange_ecdhe = 7,         // Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
    keyexchange_srp = 8,           // Secure Remote Password (SRP)
    keyexchange_eccpwd = 9,        // ECCPWD
    keyexchange_gost = 10,         // Russian cryptographic standard algorithms
    keyexchange_rsa_export = 11,   // TLS 1.0
    keyexchange_dss_export = 12,   // TLS 1.0
    keyexchange_anon_export = 13,  // TLS 1.0
    keyexchange_krb5_export = 14,  // TLS 1.0
};

// TLS authentication
enum auth_t {
    auth_null = 0,
    auth_dss = 1,       // Digital Signature Standard (DSS)
    auth_rsa = 2,       // Rivest Shamir Adleman algorithm (RSA)
    auth_anon = 3,      // Anonymous (anon)
    auth_krb5 = 4,      // Kerberos 5 (KRB5)
    auth_psk = 5,       // Pre-Shared Key (PSK)
    auth_ecdsa = 6,     // Elliptic Curve Digital Signature Algorithm (ECDSA)
    auth_sha1 = 7,      // Secure Hash Algorithm 1 with Rivest Shamir Adleman algorithm (SHA RSA)
    auth_sha2_256 = 8,  // SHA256
    auth_sha2_384 = 9,  // SHA384
    auth_eccpwd = 10,   // ECCPWD
    auth_gost = 11,     // GOST R 34.10-2012 Digital Signature Algorithm (GOSTR341012)
};

///////////////////////////////////////////////////////////////////////////
// JOSE
///////////////////////////////////////////////////////////////////////////
enum jwa_group_t {
    jwa_group_rsa = 1,
    jwa_group_aeskw = 2,
    jwa_group_dir = 3,
    jwa_group_ecdh = 4,
    jwa_group_ecdh_aeskw = 5,
    jwa_group_aesgcmkw = 6,
    jwa_group_pbes_hs_aeskw = 7,
};

/**
 * @brief Cryptographic Algorithms for Key Management
 */
enum jwa_t {
    jwa_unknown = 0,
    jwa_rsa_1_5 = 1,              // RSA1_5
    jwa_rsa_oaep = 2,             // RSA-OAEP
    jwa_rsa_oaep_256 = 3,         // RSA-OAEP-256
    jwa_a128kw = 4,               // A128KW
    jwa_a192kw = 5,               // A192KW
    jwa_a256kw = 6,               // A256KW
    jwa_dir = 7,                  // dir
    jwa_ecdh_es = 8,              // ECDH-ES
    jwa_ecdh_es_a128kw = 9,       // ECDH-ES+A128KW
    jwa_ecdh_es_a192kw = 10,      // ECDH-ES+A192KW
    jwa_ecdh_es_a256kw = 11,      // ECDH-ES+A256KW
    jwa_a128gcmkw = 12,           // A128GCMKW
    jwa_a192gcmkw = 13,           // A192GCMKW
    jwa_a256gcmkw = 14,           // A256GCMKW
    jwa_pbes2_hs256_a128kw = 15,  // PBES2-HS256+A128KW
    jwa_pbes2_hs384_a192kw = 16,  // PBES2-HS384+A192KW
    jwa_pbes2_hs512_a256kw = 17,  // PBES2-HS512+A256KW
};

enum jwe_group_t {
    jwe_group_aescbc_hs = 1,
    jwe_group_aesgcm = 2,
};

/**
 * @brief Cryptographic Algorithms for Content Encryption
 */
enum jwe_t {
    jwe_unknown = 0,
    jwe_a128cbc_hs256 = 1,  // A128CBC-HS256
    jwe_a192cbc_hs384 = 2,  // A192CBC-HS384
    jwe_a256cbc_hs512 = 3,  // A256CBC-HS512
    jwe_a128gcm = 4,        // A128GCM
    jwe_a192gcm = 5,        // A192GCM
    jwe_a256gcm = 6,        // A256GCM
};

enum jws_group_t {
    jws_group_unknown = 0,
    jws_group_hmac = 1,           // HS256, HS384, HS512
    jws_group_rsassa_pkcs15 = 2,  // RS256, RS384, RS512
    jws_group_ecdsa = 3,          // ES256, ES384, ES512
    jws_group_rsassa_pss = 4,     // PS256, PS384, PS512
    jws_group_eddsa = 5,          // EdDSA
};

/**
 * @brief Cryptographic Algorithms for Digital Signatures and MACs
 * RFC 7515 JSON Web Signature (JWS)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 */
enum jws_t {
    jws_unknown = 0,
    jws_hs256 = 1,
    jws_hs384 = 2,
    jws_hs512 = 3,
    jws_rs256 = 4,
    jws_rs384 = 5,
    jws_rs512 = 6,
    jws_es256 = 7,
    jws_es384 = 8,
    jws_es512 = 9,
    jws_ps256 = 10,
    jws_ps384 = 11,
    jws_ps512 = 12,
    jws_eddsa = 13,
};

///////////////////////////////////////////////////////////////////////////
// COSE
///////////////////////////////////////////////////////////////////////////
enum cose_key_t {
    cose_key_unknown = 0,
    // RFC 8152 Table 2: Common Header Parameters
    // RFC 8152 Table 3: Common Header Parameters
    cose_alg = 1,           // int / tstr
    cose_crit = 2,          // [+ label]
    cose_content_type = 3,  // tstr / uint
    cose_kid = 4,           // bstr
    cose_iv = 5,            // bstr
    cose_partial_iv = 6,    // bstr

    cose_counter_sig = 7,  // COSE_Signature / [+ COSE_Signature]

    // RFC 8152 Table 27: Header Parameter for CounterSignature0
    cose_counter_sig0 = 9,

    // RFC 9338 Table 1: Common Header Parameters
    // RFC 9338 Table 2: New Common Header Parameters
    cose_counter_sig_v2 = 11,
    cose_counter_sig0_v2 = 12,

    // RFC 9360 Table 1: X.509 COSE Header Parameters
    cose_x5bag = 32,
    cose_x5chain = 33,
    cose_x5t = 34,
    cose_x5u = 35,

    // RFC 8152 Table 19: ECDH Algorithm Parameters
    // RFC 9053 Table 15: ECDH Algorithm Parameters
    cose_ephemeral_key = -1,
    cose_static_key = -2,
    cose_static_key_id = -3,

    // RFC 8152 Table 13: HKDF Algorithm Parameters
    // RFC 9053 Table 9: HKDF Algorithm Parameters
    cose_salt = -20,

    // RFC 8152 Table 14: Context Algorithm Parameters
    // RFC 9053 Table 10: Context Algorithm Parameters
    cose_partyu_id = -21,
    cose_partyu_nonce = -22,
    cose_partyu_other = -23,
    cose_partyv_id = -24,
    cose_partyv_nonce = -25,
    cose_partyv_other = -26,

    // RFC 9360 Table 2: Static ECDH Algorithm Values
    cose_x5t_sender = -27,
    cose_x5u_sender = -28,
    cose_x5chain_sender = -29,
};
enum cose_key_lable_t {
    // RFC 8152 Table 3: Key Map Labels
    // RFC 8152 Table 4: Key Map Labels
    cose_lable_kty = 1,
    cose_lable_kid = 2,
    cose_lable_alg = 3,
    cose_lable_keyops = 4,
    cose_lable_base_iv = 5,

    // RFC 8152 Table 23: EC Key Parameters
    // RFC 9053 Table 19: EC Key Parameters
    // cose_kty_t::cose_kty_ec2
    cose_ec_crv = -1,
    cose_ec_x = -2,
    cose_ec_y = -3,
    cose_ec_d = -4,

    // RFC 8152 Table 24: Octet Key Pair Parameters
    // RFC 9053 Table 20: Octet Key Pair Parameters
    // cose_kty_t::cose_kty_okp
    cose_okp_crv = -1,
    cose_okp_x = -2,
    cose_okp_d = -4,

    // RFC 8152 Table 25: Symmetric Key Parameters
    // RFC 9053 Table 21: Symmetric Key Parameters
    cose_symm_k = -1,

    // RSA 8230 Table 4: RSA Key Parameters
    cose_rsa_n = -1,
    cose_rsa_e = -2,
    cose_rsa_d = -3,
    cose_rsa_p = -4,
    cose_rsa_q = -5,
    cose_rsa_dp = -6,
    cose_rsa_dq = -7,
    cose_rsa_qi = -8,
    cose_rsa_other = -9,
    cose_rsa_ri = -10,
    cose_rsa_di = -11,
    cose_rsa_ti = -12,
};

enum cose_kty_t {
    // RFC 8152 Table 21: Key Type Values
    // RFC 9053 Table 17: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    cose_kty_unknown = 0,
    cose_kty_okp = 1,
    cose_kty_ec2 = 2,
    cose_kty_symm = 4,

    // RFC 8230 Table 3: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    cose_kty_rsa = 3,

    // RFC 9053 Table 22: Key Type Capabilities
    cose_kty_hss_lms = 5,
    cose_kty_walnutdsa = 6,
};
enum cose_keyop_t {
    // RFC 8152 Table 4: Key Operation Values
    // RFC 8152 Table 5: Key Operation Values
    cose_keyop_sign = 1,
    cose_keyop_verify = 2,
    cose_keyop_encrypt = 3,
    cose_keyop_decrypt = 4,
    cose_keyop_wrap = 5,
    cose_keyop_unwrap = 6,
    cose_keyop_derive_key = 7,
    cose_keyop_derive_bits = 8,
    cose_keyop_mac_create = 9,
    cose_keyop_mac_verify = 10,
};

/**
 * @sa  crypto_key::generate_cose
 */
enum cose_ec_curve_t {
    cose_ec_unknown = 0,
    // RFC 8152 Table 22: Elliptic Curves
    // RFC 9053 Table 18: Elliptic Curves
    cose_ec_p256 = 1,
    cose_ec_p384 = 2,
    cose_ec_p521 = 3,
    cose_ec_x25519 = 4,
    cose_ec_x448 = 5,
    cose_ec_ed25519 = 6,
    cose_ec_ed448 = 7,
    cose_ec_secp256k1 = 8,  // RFC 8812 4.2.  COSE Elliptic Curves Registrations "secp256k1"
};

enum crypt_category_t {
    crypt_category_not_classified = 0,
    crypt_category_unknown = crypt_category_not_classified,
    crypt_category_crypt = 1,
    crypt_category_mac = 2,
    crypt_category_sign = 3,
    crypt_category_hash = 4,
    crypt_category_keydistribution = 5,
};

enum cose_group_t {
    // RFC 8152 8. Signature Algorithms
    //   8.1.  ECDSA
    //   Table 5, ES256, ES284, ES512
    cose_group_sign_ecdsa = 1,
    // RFC 8152 8. Signature Algorithms
    //   8.2.  Edwards-Curve Digital Signature Algorithms (EdDSAs)
    //   Table 6, EdDSA
    cose_group_sign_eddsa = 2,
    // RFC 8152 9. Message Authentication Code (MAC) Algorithms
    //   9.1.  Hash-Based Message Authentication Codes (HMACs)
    //   Table 7, HMAC 256/64, HMAC 256/256, HMAC 384/384, HMAC 512/512
    cose_group_mac_hmac = 3,
    // RFC 8152 9. Message Authentication Code (MAC) Algorithms
    //   9.2.  AES Message Authentication Code (AES-CBC-MAC)
    //   Table 8, AES-MAC 128/64, AES-MAC 256/64, AES-MAC 128/128, AES-MAC 256/128
    cose_group_mac_aes = 4,
    // RFC 8152 10. Content Encryption Algorithms
    //   10.1.  AES GCM
    //   Table 9, A128GCM, A192GCM, A256GCM
    cose_group_enc_aesgcm = 5,
    // RFC 8152 10. Content Encryption Algorithms
    //   10.2.  AES CCM
    //   Table 10, AES-CCM-16-64-128, ...
    cose_group_enc_aesccm = 6,
    // RFC 8152 10. Content Encryption Algorithms
    //   10.3.  ChaCha20 and Poly1305
    //   Table 11, ChaCha20/Poly1305
    cose_group_enc_chacha20_poly1305 = 7,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.1. Direct Encryption
    //   12.1.1.  Direct Key
    //   Table 15, direct
    cose_group_key_direct = 8,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.1. Direct Encryption
    //   12.1.2.  Direct Key with KDF
    //   Table 16, direct+HKDF-SHA-256, direct+HKDF-SHA-512
    cose_group_key_hkdf_hmac = 9,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.1. Direct Encryption
    //   12.1.2.  Direct Key with KDF
    //   Table 16,  direct+HKDF-AES-128, direct+HKDF-AES-256
    cose_group_key_hkdf_aes = 10,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.2. Key Wrap
    //   12.2.1.  AES Key Wrap
    //   Table 17, A128KW, A192KW, A256KW
    cose_group_key_aeskw = 11,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.4. Direct Key Agreement
    //   12.4.1.  ECDH
    //   Table 18 ECDH-ES+HKDF-256, ECDH-ES+HKDF-512, ECDH-SS+HKDF-256, ECDH-SS+HKDF-512
    cose_group_key_ecdhes_hmac = 12,
    cose_group_key_ecdhss_hmac = 13,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.5. Key Agreement with Key Wrap
    //   12.5.1.  ECDH
    //   Table 20 ECDH-ES+A128KW,ECDH-ES+A192KW, ECDH-ES+A256KW, ECDH-SS+A128KW,ECDH-SS+A192KW, ECDH-SS+A256KW
    cose_group_key_ecdhes_aeskw = 14,
    cose_group_key_ecdhss_aeskw = 15,
    // RFC 8230 2.  RSASSA-PSS Signature Algorithm
    //   Table 1, PS256, PS384, PS512
    cose_group_sign_rsassa_pss = 16,
    // RFC 8230 3.  RSAES-OAEP Key Encryption Algorithm
    //   Table 2, RSAES-OAEP w/ SHA-1, RSAES-OAEP w/ SHA-256, RSAES-OAEP w/ SHA-512
    cose_group_key_rsa_oaep = 17,
    // RFC 8812 2.  RSASSA-PKCS1-v1_5 Signature Algorithm
    //   Table 1, RS256, RS384, RS512, RS1
    cose_group_sign_rsassa_pkcs15 = 18,
    // RFC 9053 10.  IANA Considerations
    //   10.2.  Changes to the "COSE Algorithms" Registry
    //   Table 23, IV-GENERATION
    cose_group_iv_generate = 19,
    // RFC 9054 3.  Hash Algorithm Identifiers
    //   Table 1, SHA-1
    //   Table 2, SHA-256/64, SHA-256, SHA-384, SHA-512, SHA-512/256
    cose_group_hash = 20,
};
enum cose_alg_t {
    cose_unknown = 0,

    // RFC 8152 Table 17: AES Key Wrap Algorithm Values
    // RFC 9053 Table 13: AES Key Wrap Algorithm Values
    cose_aes128kw = -3,  // "A128KW"
    cose_aes192kw = -4,  // "A192KW"
    cose_aes256kw = -5,  // "A256KW"

    // RFC 8152 Table 15: Direct Key
    // RFC 9053 Table 11: Direct Key
    cose_direct = -6,  // "direct"

    // RFC 8152 Table 5: ECDSA Algorithm Values
    // RFC 9053 Table 1: ECDSA Algorithm Values
    cose_es256 = -7,   // "ES256", ECDSA w/ SHA-256
    cose_es384 = -35,  // "ES384", ECDSA w/ SHA-384
    cose_es512 = -36,  // "ES512", ECDSA w/ SHA-512

    // RFC 8152 Table 6: EdDSA Algorithm Values
    // RFC 9053 Table 2: EdDSA Algorithm Value
    cose_eddsa = -8,  // "EdDSA"

    // RFC 8152 Table 16: Direct Key with KDF
    // RFC 9053 Table 8: HKDF Algorithms
    // RFC 9053 Table 12: Direct Key with KDF
    cose_hkdf_sha256 = -10,  // "HKDF SHA-256", "direct+HKDF-SHA-256"
    cose_hkdf_sha512 = -11,  // "HKDF SHA-512", "direct+HKDF-SHA-512"
    cose_hkdf_aes128 = -12,  // "HKDF AES-MAC-128", "direct+HKDF-AES-128"
    cose_hkdf_aes256 = -13,  // "HKDF AES-MAC-256", "direct+HKDF-AES-256"

    // RFC 9054 Table 1: SHA-1 Hash Algorithm
    cose_sha1 = -14,  // "SHA-1"

    // RFC 9054 Table 2: SHA-2 Hash Algorithms
    cose_sha256_64 = -15,   // "SHA-256/64"
    cose_sha256 = -16,      // "SHA-256"
    cose_sha512_256 = -17,  // "SHA-512/256"
    cose_sha384 = -43,      // "SHA-384"
    cose_sha512 = -44,      // "SHA-512"

    // RFC 9054 Table 3: SHAKE Hash Functions
    cose_shake128 = -18,  // "SHAKE128"
    cose_shake256 = -45,  // "SHAKE256"

    // RFC 8152 Table 18: ECDH Algorithm Values
    // RFC 9053 Table 14: ECDH Algorithm Values
    cose_ecdhes_hkdf_256 = -25,  // "ECDH-ES", "ECDH-ES + HKDF-256"
    cose_ecdhes_hkdf_512 = -26,  // "ECDH-ES-512", "ECDH-ES + HKDF-512"
    cose_ecdhss_hkdf_256 = -27,  // "ECDH-SS", "ECDH-SS + HKDF-256"
    cose_ecdhss_hkdf_512 = -28,  // "ECDH-SS-512", "ECDH-SS + HKDF-512"

    // RFC 8152 Table 20: ECDH Algorithm Values with Key Wrap
    // RFC 9053 Table 16: ECDH Algorithm Values with Key Wrap
    cose_ecdhes_a128kw = -29,  // "ECDH-ES-A128KW"
    cose_ecdhes_a192kw = -30,  // "ECDH-ES-A192KW"
    cose_ecdhes_a256kw = -31,  // "ECDH-ES-A256KW"
    cose_ecdhss_a128kw = -32,  // "ECDH-SS-A128KW"
    cose_ecdhss_a192kw = -33,  // "ECDH-SS-A192KW"
    cose_ecdhss_a256kw = -34,  // "ECDH-SS-A256KW"

    // RFC 8230 Table 1: RSASSA-PSS Algorithm Values
    cose_ps256 = -37,  // "RSA-PSS-256"
    cose_ps384 = -38,  // "RSA-PSS-384"
    cose_ps512 = -39,  // "RSA-PSS-512"

    // RFC 8230 Table 2: RSAES-OAEP Algorithm Values
    cose_rsaoaep1 = -40,    // "RSA-OAEP"
    cose_rsaoaep256 = -41,  // "RSA-OAEP-256"
    cose_rsaoaep512 = -42,  // "RSA-OAEP-512"

    // HSS-LMS
    cose_hss_lms = -46,

    // RFC 8812 Table 2: ECDSA Algorithm Values
    cose_es256k = -47,  // "ES256K"

    // RFC 8812 Table 1: RSASSA-PKCS1-v1_5 Algorithm Values
    cose_rs256 = -257,  // "RS256"
    cose_rs384 = -258,  // "RS384"
    cose_rs512 = -259,  // "RS512"
    cose_rs1 = -65535,  // "RS1", deprecated RFC 8812 5.3.

    // RFC 9459 CBOR Object Signing and Encryption (COSE): AES-CTR and AES-CBC
    cose_aes128ctr = -65534,  // RFC 9459 4.2 deprecated
    cose_aes192ctr = -65533,  // RFC 9459 4.2 deprecated
    cose_aes256ctr = -65532,  // RFC 9459 4.2 deprecated
    cose_aes128ccb = -65531,  // RFC 9459 5.2 deprecated
    cose_aes192ccb = -65530,  // RFC 9459 5.2 deprecated
    cose_aes256ccb = -65529,  // RFC 9459 5.2 deprecated

    // RFC 8152 Table 9: Algorithm Value for AES-GCM
    // RFC 9053 Table 5: Algorithm Values for AES-GCM
    cose_aes128gcm = 1,  // "A128GCM"
    cose_aes192gcm = 2,  // "A192GCM"
    cose_aes256gcm = 3,  // "A256GCM"

    // RFC 8152 Table 7: HMAC Algorithm Values
    // RFC 9053 Table 3: HMAC Algorithm Values
    cose_hs256_64 = 4,  // "HS256/64", HMAC w/ SHA-256 truncated to 64 bits, When truncating, the leftmost tag length bits are kept and transmitted.
    cose_hs256 = 5,     // "HS256/256", HMAC w/ SHA-256
    cose_hs384 = 6,     // "HS384/384", HMAC w/ SHA-384
    cose_hs512 = 7,     // "HS512/512", HMAC w/ SHA-512

    // RFC 8152 Table 10: Algorithm Values for AES-CCM
    // RFC 9053 Table 6: Algorithm Values for AES-CCM
    cose_aesccm_16_64_128 = 10,   // "AES-CCM-16-64-128"
    cose_aesccm_16_64_256 = 11,   // "AES-CCM-16-64-256"
    cose_aesccm_64_64_128 = 12,   // "AES-CCM-64-64-128"
    cose_aesccm_64_64_256 = 13,   // "AES-CCM-64-64-256"
    cose_aesccm_16_128_128 = 30,  // "AES-CCM-16-128-128"
    cose_aesccm_16_128_256 = 31,  // "AES-CCM-16-128-256"
    cose_aesccm_64_128_128 = 32,  // "AES-CCM-64-128-128"
    cose_aesccm_64_128_256 = 33,  // "AES-CCM-64-128-256"

    // RFC 8152 Table 8: AES-MAC Algorithm Values
    // RFC 9053 Table 4: AES-MAC Algorithm Values
    cose_aesmac_128_64 = 14,   // "AES-MAC-128/64", AES-MAC 128-bit key, 64-bit tag
    cose_aesmac_256_64 = 15,   // "AES-MAC-256/64", AES-MAC 256-bit key, 64-bit tag
    cose_aesmac_128_128 = 25,  // "AES-MAC-128/128", AES-MAC 128-bit key, 128-bit tag
    cose_aesmac_256_128 = 26,  // "AES-MAC-256/128", AES-MAC 256-bit key, 128-bit tag

    // RFC 8152 Table 11: Algorithm Value for AES-GCM
    // RFC 9053 Table 7: Algorithm Value for ChaCha20/Poly1305
    cose_chacha20_poly1305 = 24,  // "ChaCha20/Poly1305"

    // RFC 9053 Table 23: New entry in the COSE Algorithms registry
    cose_iv_generation = 34,  // "IV-GENERATION"
};

enum cose_hint_flag_t {
    cose_hint_sign = 1 << 0,
    cose_hint_enc = 1 << 1,
    cose_hint_mac = 1 << 2,
    cose_hint_hash = 1 << 3,
    cose_hint_agree = 1 << 4,
    cose_hint_iv = 1 << 5,
    cose_hint_salt = 1 << 6,
    cose_hint_party = 1 << 7,
    cose_hint_kek = 1 << 8,
    cose_hint_epk = 1 << 9,
    cose_hint_static_key = 1 << 10,
    cose_hint_static_kid = 1 << 11,
    cose_hint_kty_ec = 1 << 12,
    cose_hint_kty_okp = 1 << 13,
    cose_hint_kty_rsa = 1 << 14,
    cose_hint_kty_oct = 1 << 15,
    cose_hint_not_supported = 1 << 16,
};

///////////////////////////////////////////////////////////////////////////
// crypt
///////////////////////////////////////////////////////////////////////////
typedef struct _hint_blockcipher_t {
    crypt_algorithm_t algorithm;
    uint16 keysize;    // size of key
    uint16 ivsize;     // size of initial vector
    uint16 blocksize;  // blocksize for en/de-cryption
    uint16 blockkw;    // blocksize for keywrap (AES)
} hint_blockcipher_t;

crypt_algorithm_t typeof_alg(const hint_blockcipher_t* hint);
uint16 sizeof_key(const hint_blockcipher_t* hint);
uint16 sizeof_iv(const hint_blockcipher_t* hint);
uint16 sizeof_block(const hint_blockcipher_t* hint);
uint16 sizeof_blockkw(const hint_blockcipher_t* hint);

typedef struct _hint_cipher_t {
    crypt_algorithm_t algorithm;
    crypt_mode_t mode;
    const char* fetchname;
} hint_cipher_t;
crypt_algorithm_t typeof_alg(const hint_cipher_t* hint);
crypt_mode_t typeof_mode(const hint_cipher_t* hint);
const char* nameof_alg(const hint_cipher_t* hint);

struct _crypt_context_t {};
typedef struct _crypt_context_t crypt_context_t;

///////////////////////////////////////////////////////////////////////////
// digest, MAC
///////////////////////////////////////////////////////////////////////////
typedef struct _hint_digest_t {
    hash_algorithm_t algorithm;
    const char* fetchname;
    uint16 digest_size;
} hint_digest_t;

hash_algorithm_t typeof_alg(const hint_digest_t* hint);
const char* nameof_alg(const hint_digest_t* hint);
uint16 sizeof_digest(const hint_digest_t* hint);

struct _hash_context_t {};
typedef struct _hash_context_t hash_context_t;

struct _otp_context_t {};
typedef struct _otp_context_t otp_context_t;

///////////////////////////////////////////////////////////////////////////
// sign
///////////////////////////////////////////////////////////////////////////
typedef struct _hint_signature_t {
    crypt_sig_t sig_type;  // ex. sig_eddsa
    jws_t jws_type;        // ex. jws_eddsa
    jws_group_t group;     // ex. jws_group_eddsa
    crypto_kty_t kty;      // ex. kty_okp
    const char* jws_name;  // ex. "EdDSA"
    hash_algorithm_t alg;  // ex. hash_alg_unknown
    uint32 count;          // ex. 2
    uint32 nid[2];         // ex. NID_ED25519, NID_ED448
} hint_signature_t;

crypt_sig_t typeof_sig(const hint_signature_t* hint);
jws_t typeof_jws(const hint_signature_t* hint);
jws_group_t typeof_group(const hint_signature_t* hint);
crypto_kty_t typeof_kty(const hint_signature_t* hint);
const char* nameof_jws(const hint_signature_t* hint);
hash_algorithm_t typeof_alg(const hint_signature_t* hint);

///////////////////////////////////////////////////////////////////////////
// curve
///////////////////////////////////////////////////////////////////////////
#define ECDSA_SUPPORT_SHA1 0x0001
#define ECDSA_SUPPORT_SHA2_224 0x0002
#define ECDSA_SUPPORT_SHA2_256 0x0004
#define ECDSA_SUPPORT_SHA2_384 0x0008
#define ECDSA_SUPPORT_SHA2_512 0x0010
#define CURVE_SUPPORT_JOSE 0x1000
#define CURVE_SUPPORT_COSE 0x2000

enum curve_category_t : uint8 {
    prime_field_weierstrass_curve = (1 << 0),   // general curve
    binary_field_weierstrass_curve = (1 << 1),  // embeded device
    koblitz_curve = (1 << 2),                   // IoT, smart card
    montgomery_curve = (1 << 3),                // key exchange
    edwards_curve = (1 << 4),                   // digital signature
};

/**
 * @brief  curve information
 *              nid         openssl nid             NID_X9_62_prime256v1
 *              cose_crv    cose curve              cose_ec_p256
 *              kty         key type                kty_ec
 *              use         usage(enc, sig)         use_any
 *              group       TLS supported group     0x0017
 *              oid         OID
 *              name        NIST
 *              aka1        X9.62, X9.63
 *              aka2        Standards for Efficient Cryptography (SEC)
 *              aka3
 * @remarks
 *         references
 *             TLS supported groups
 *                 https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 *             Standard curve database - NIST, ANSI X9.62 & X9.63, SECG, ...
 *                 https://neuromancer.sk/std/
 *
 *          Verifiably random algorithms
 *              ANSI X9.62
 *              SECG
 *              NIST
 *              Brainpool
 *          Pairing-friendly curves
 *              BN
 *              BLS
 *              MNT
 *              KSS
 *          Other
 *              Complex multiplication
 */
typedef struct _hint_curves_t {
    uint32 nid;  // openssl NID
    cose_ec_curve_t cose_crv;
    crypto_kty_t kty;  // kty_ec, kty_okp
    crypto_use_t use;  // use_any, use_enc, use_sig
    uint16 tlsgroup;   // TLS group
    uint16 flags;      // ECDSA_SUPPORT_xxx
    uint8 keysize;     // key size (preserve leading zero), (keysize-2 .. keysize)
    uint8 category;    // see curve_category_t
    const char* oid;   // OID, https://neuromancer.sk/
    const char* name;  // NIST (CURVE P-256, P-384, P-521, ...)
    const char* aka1;  // X9.62, X9.63 (ansip384r1, ansip521r1, ...)
    const char* aka2;  // Standards for Efficient Cryptography (SEC) (secp256r1, secp384r1, secp521r1, ...)
    const char* aka3;
} hint_curve_t;
uint32 nidof(const hint_curve_t* hint);
cose_ec_curve_t coseof(const hint_curve_t* hint);
crypto_kty_t ktyof(const hint_curve_t* hint);
uint16 tlsgroupof(const hint_curve_t* hint);
uint8 keysizeof(const hint_curve_t* hint);
const char* oidof(const hint_curve_t* hint);
bool support(const hint_curve_t* hint, hash_algorithm_t alg);

///////////////////////////////////////////////////////////////////////////
// key
///////////////////////////////////////////////////////////////////////////
typedef struct _hint_kty_name_t {
    crypto_kty_t kty;
    const char* name;
} hint_kty_name_t;

typedef std::map<crypt_item_t, binary_t> crypt_datamap_t;
typedef std::map<crypt_item_t, variant_t> crypt_variantmap_t;

///////////////////////////////////////////////////////////////////////////
// JOSE
///////////////////////////////////////////////////////////////////////////
typedef struct _hint_jose_encryption_t {
    const char* alg_name;

    int type;          // jwa_t, jwe_t
    int group;         // jwa_group_t, jwe_group_t
    crypto_kty_t kty;  // crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec, crypto_kty_t::kty_oct
    crypto_kty_t alt;  // for example crypto_kty_t::kty_okp, if kt is crypto_kty_t::kty_ec
    int mode;          // crypt_enc_t::rsa_1_5, crypt_enc_t::rsa_oaep, crypt_enc_t::rsa_oaep256

    crypt_algorithm_t crypt_alg;  // algorithm for keywrap or GCM
    crypt_mode_t crypt_mode;      // crypt_mode_t::wrap, crypt_mode_t::gcm
    int keysize;                  // 16, 24, 32
    int hash_alg;
} hint_jose_encryption_t;
const char* nameof_alg(const hint_jose_encryption_t* hint);

enum jose_serialization_t {
    jose_compact = 0,
    jose_json = 1,
    jose_flatjson = 2,
};
#define JOSE_JSON_FORMAT jose_serialization_t::jose_flatjson

///////////////////////////////////////////////////////////////////////////
// COSE
///////////////////////////////////////////////////////////////////////////
typedef struct _hint_cose_group_t {
    cose_group_t group;
    crypt_category_t category;
    uint32 hintflags;  // combinations of cose_hint_flag_t
} hint_cose_group_t;

typedef struct _hint_cose_algorithm_t {
    cose_alg_t alg;
    const char* name;
    crypto_kty_t kty;
    cose_group_t group;
    const hint_cose_group_t* hint_group;
    struct _eckey {
        uint16 nid;
        cose_ec_curve_t curve;
    } eckey;
    struct _dgst {
        const char* algname;
        uint16 dlen;
        uint16 klen;
    } dgst;
    struct _enc {
        const char* algname;
        uint16 ksize;
        uint16 tsize;
        uint16 lsize;
    } enc;
} hint_cose_algorithm_t;

struct cose_algorithm_param_t {
    int32 label;
    const char* name;
};

///////////////////////////////////////////////////////////////////////////
// openssl
///////////////////////////////////////////////////////////////////////////
enum crypt_poweredby_t {
    openssl = 1,
};

/* nid (use openssl nid definition for convenience) */
enum nid_t : uint32 {
    nid_oct = 855,         // EVP_PKEY_HMAC, NID_hmac
    nid_rsa = 6,           // EVP_PKEY_RSA, NID_rsaEncryption
    nid_rsa2 = 19,         // EVP_PKEY_RSA2, NID_rsa
    nid_rsapss = 912,      // EVP_PKEY_RSA_PSS, NID_rsassaPss
    nid_ffdhe2048 = 1126,  // NID_ffdhe2048
    nid_ffdhe3072 = 1127,  // NID_ffdhe3072
    nid_ffdhe4096 = 1128,  // NID_ffdhe4096
    nid_ffdhe6144 = 1129,  // NID_ffdhe6144
    nid_ffdhe8192 = 1130,  // NID_ffdhe8192
    nid_dh = 28,           // NID_dhKeyAgreement (EVP_PKEY_DH)
    nid_dsa = 116,         // NID_dsa
};

enum authenticated_encryption_flag_t : uint16 {
    tls_mac_then_encrypt = 0x0001,
    jose_encrypt_then_mac = 0x8001,
    tls_encrypt_then_mac = 0x8002,
};

}  // namespace crypto
}  // namespace hotplace

#endif
