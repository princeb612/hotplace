/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_TYPES__
#define __HOTPLACE_SDK_CRYPTO_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/encoding/base64.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/io/types.hpp>
#include <list>
#include <map>

namespace hotplace {
using namespace io;
namespace crypto {

#define CRYPTO_SCHEME_CATEGORY_CBCHMAC 0x01000000
#define CRYPTO_SCHEME_CATEGORY_TLS 0x02000000
#define CRYPTO_SCHEME_HINT_CCM8 0x00010000

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
enum class crypt_algorithm_t : uint8 {
    unknown = 0,

    aes128 = 0x01,
    aes192 = 0x02,
    aes256 = 0x03,
    aria128 = 0x04,
    aria192 = 0x05,
    aria256 = 0x06,
    camellia128 = 0x07,
    camellia192 = 0x08,
    camellia256 = 0x09,
    chacha20 = 0x0a,

    blowfish = 0xa1,
    cast = 0xa2,
    des = 0xa3,
    idea = 0xa4,
    rc2 = 0xa5,
    rc5 = 0xa6,
    seed = 0xa7,
    sm4 = 0xa8,
    rc4 = 0xa9,
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
 *  sample
 *      auto cipher = EVP_CIPHER_fetch(nullptr, "aes-128-ccm", nullptr);
 *      EVP_CIPHER_CTX_init(context);
 *      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 8, nullptr);
 *      EVP_CIPHER_free(cipher);
 */
enum class crypt_mode_t : uint8 {
    unknown = 0,

    ecb = 1,
    cbc = 2,
    cfb = 3,
    cfb1 = 4,
    cfb8 = 5,
    ofb = 6,
    ctr = 7,
    gcm = 8,
    wrap = 9,
    ccm = 10,  // 14-octet authentication tag

    poly1305 = 12,
};

enum class crypt_enc_t {
    unknown = 0,

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
enum class hash_algorithm_t : uint8 {
    unknown = 0,

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
/**
 * @sa  crypto_sign_builder, hint_sigscheme_t
 */
enum class sig_category_t : uint8 {
    unknown = 0,
    dgst = 1,           //
    hmac = 2,           // HMAC (kty_oct)
    rsassa_pkcs15 = 3,  // PKCS#1 Ver1.5 (kty_rsa)
    ecdsa = 4,          // Elliptic Curve Digital Signature Algorithm (ECDSA)
    rsassa_pss = 5,     // PKCS#1 RSASSA-PSS (kty_rsa, kty_rsapss)
    eddsa = 6,          // Edwards-Curve Digital Signature Algorithms (EdDSAs)
    dsa = 7,            // DSA
    rsassa_x931 = 8,    // FIPS186-3, X9.31
    mldsa = 9,          // MLDSA
    brainpool = 10,     // RFC 8734
    slhdsa = 11,        // SHL-DSA
};

constexpr uint16 make_sigscheme(sig_category_t c, hash_algorithm_t h) { return static_cast<uint16>((t_underlying(c) << 8) | t_underlying(h)); }
constexpr uint16 make_sigscheme(sig_category_t c, uint8 h) { return static_cast<uint16>((t_underlying(c) << 8) | h); }
/**
 * (sig_category_t << 8) | hash_algorithm_t
 */
enum class signature_t : uint16 {
    unknown = 0,

    hs256 = make_sigscheme(sig_category_t::hmac, hash_algorithm_t::sha2_256),
    hs384 = make_sigscheme(sig_category_t::hmac, hash_algorithm_t::sha2_384),
    hs512 = make_sigscheme(sig_category_t::hmac, hash_algorithm_t::sha2_512),

    rs256 = make_sigscheme(sig_category_t::rsassa_pkcs15, hash_algorithm_t::sha2_256),
    rs384 = make_sigscheme(sig_category_t::rsassa_pkcs15, hash_algorithm_t::sha2_384),
    rs512 = make_sigscheme(sig_category_t::rsassa_pkcs15, hash_algorithm_t::sha2_512),
    rs1 = make_sigscheme(sig_category_t::rsassa_pkcs15, hash_algorithm_t::sha1),

    es256 = make_sigscheme(sig_category_t::ecdsa, hash_algorithm_t::sha2_256),
    es384 = make_sigscheme(sig_category_t::ecdsa, hash_algorithm_t::sha2_384),
    es512 = make_sigscheme(sig_category_t::ecdsa, hash_algorithm_t::sha2_512),

    ps256 = make_sigscheme(sig_category_t::rsassa_pss, hash_algorithm_t::sha2_256),
    ps384 = make_sigscheme(sig_category_t::rsassa_pss, hash_algorithm_t::sha2_384),
    ps512 = make_sigscheme(sig_category_t::rsassa_pss, hash_algorithm_t::sha2_512),

    eddsa = make_sigscheme(sig_category_t::eddsa, hash_algorithm_t{}),

    sha1 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::sha1),
    sha224 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::sha2_224),
    sha256 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::sha2_256),
    sha384 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::sha2_384),
    sha512 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::sha2_512),
    shake128 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::shake128),
    shake256 = make_sigscheme(sig_category_t::dgst, hash_algorithm_t::shake256),

    es256k = make_sigscheme(sig_category_t::ecdsa, hash_algorithm_t::sha2_256),  // ES256K, NID_secp256k1

    mldsa44 = make_sigscheme(sig_category_t::mldsa, 0xf1),  // NIST security level 2
    mldsa65 = make_sigscheme(sig_category_t::mldsa, 0xf2),  // NIST security level 3
    mldsa87 = make_sigscheme(sig_category_t::mldsa, 0xf3),  // NIST security level 5

    brainpool256 = make_sigscheme(sig_category_t::brainpool, hash_algorithm_t::sha2_256),
    brainpool384 = make_sigscheme(sig_category_t::brainpool, hash_algorithm_t::sha2_384),
    brainpool512 = make_sigscheme(sig_category_t::brainpool, hash_algorithm_t::sha2_512),

    slhdsa_sha2_128s = make_sigscheme(sig_category_t::slhdsa, 0xf1),
    slhdsa_sha2_128f = make_sigscheme(sig_category_t::slhdsa, 0xf2),
    slhdsa_sha2_192s = make_sigscheme(sig_category_t::slhdsa, 0xf3),
    slhdsa_sha2_192f = make_sigscheme(sig_category_t::slhdsa, 0xf4),
    slhdsa_sha2_256s = make_sigscheme(sig_category_t::slhdsa, 0xf5),
    slhdsa_sha2_256f = make_sigscheme(sig_category_t::slhdsa, 0xf6),
    slhdsa_shake_128s = make_sigscheme(sig_category_t::slhdsa, 0xf7),
    slhdsa_shake_128f = make_sigscheme(sig_category_t::slhdsa, 0xf8),
    slhdsa_shake_192s = make_sigscheme(sig_category_t::slhdsa, 0xf9),
    slhdsa_shake_192f = make_sigscheme(sig_category_t::slhdsa, 0xfa),
    slhdsa_shake_256s = make_sigscheme(sig_category_t::slhdsa, 0xfb),
    slhdsa_shake_256f = make_sigscheme(sig_category_t::slhdsa, 0xfc),
};

///////////////////////////////////////////////////////////////////////////
// curve
// ec_curve_t        - openssl numeric identifier
// tls_group_t - TLS Supported Groups
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

/**
 * RFC 8446 4.2.7.  Supported Groups
 * RFC 8422 5.1.1.  Supported Elliptic Curves Extension
 * tls_extension_type_t::supported_groups
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
enum class tls_group_t : uint16 {
    unknown = 0x0000,
    // deprecated (1..22), reserved (0xFE00..0xFEFF), deprecated(0xFF01..0xFF02)
    // cf. hint_curves define tls_group_t::sect163k1..tls_group_t::x448

    sect163k1 = 0x0001,
    sect163r1 = 0x0002,
    sect163r2 = 0x0003,
    sect193r1 = 0x0004,
    sect193r2 = 0x0005,
    sect233k1 = 0x0006,
    sect233r1 = 0x0007,
    sect239k1 = 0x0008,
    sect283k1 = 0x0009,
    sect283r1 = 0x000a,             // 10
    sect409k1 = 0x000b,             // 11
    sect409r1 = 0x000c,             // 12
    sect571k1 = 0x000d,             // 13
    sect571r1 = 0x000e,             // 14
    secp160k1 = 0x000f,             // 15
    secp160r1 = 0x0010,             // 16
    secp160r2 = 0x0011,             // 17
    secp192k1 = 0x0012,             // 18
    secp192r1 = 0x0013,             // 19
    secp224k1 = 0x0014,             // 20
    secp224r1 = 0x0015,             // 21
    secp256k1 = 0x0016,             // 22
    secp256r1 = 0x0017,             // 23
    secp384r1 = 0x0018,             // 24
    secp521r1 = 0x0019,             // 25
    brainpoolP256r1 = 0x001a,       // 26
    brainpoolP384r1 = 0x001b,       // 27
    brainpoolP512r1 = 0x001c,       // 28
    x25519 = 0x001d,                // 29
    x448 = 0x001e,                  // 30
    brainpoolP256r1tls13 = 0x001f,  // 31
    brainpoolP384r1tls13 = 0x0020,  // 32
    brainpoolP512r1tls13 = 0x0021,  // 33
    GC256A = 0x0022,                // 34
    GC256B = 0x0023,                // 35
    GC256C = 0x0024,                // 36
    GC256D = 0x0025,                // 37
    GC512A = 0x0026,                // 38
    GC512B = 0x0027,                // 39
    GC512C = 0x0028,                // 40
    curveSM2 = 0x0029,              // 41, not recommended
    ffdhe2048 = 0x0100,             // 256
    ffdhe3072 = 0x0101,             // 257
    ffdhe4096 = 0x0102,             // 258
    ffdhe6144 = 0x0103,             // 259
    ffdhe8192 = 0x0104,             // 260
    mlkem512 = 0x0200,              // 512  FIPS 203 version of ML-KEM-512
    mlkem768 = 0x0201,              // 513  FIPS 203 version of ML-KEM-768
    mlkem1024 = 0x0202,             // 514  FIPS 203 version of ML-KEM-1024
    secp256r1mlkem768 = 0x11eb,     // 4587 Combining secp256r1 ECDH with ML-KEM-768
    x25519mlkem768 = 0x11ec,        // 4588 Combining X25519 ECDH with ML-KEM-768
    secp384r1mlkem1024 = 0x11ed,    // 4589 Combining secp384r1 ECDH with ML-KEM-1024

    arbitrary_explicit_prime_curves = 0xff01,  // arbitrary_explicit_prime_curves
    arbitrary_explicit_char2_curves = 0xff02,  // arbitrary_explicit_char2_curves
};

/**
 * RFC 8446 4.2.3.  Signature Algorithms
 * tls_extension_type_t::signature_algorithms
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
enum class tls_sigscheme_t : uint16 {
    unknown = 0,

    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* RFC 8394 */
    ecdsa_brainpoolP256r1tls13_sha256 = 0x81a,
    ecdsa_brainpoolP384r1tls13_sha384 = 0x81b,
    ecdsa_brainpoolP512r1tls13_sha512 = 0x81c,

    /* Legacy algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    /* https://www.iana.org/go/draft-ietf-tls-mldsa-00 */
    mldsa44 = 0x904,
    mldsa65 = 0x905,
    mldsa87 = 0x906,

    slhdsa_sha2_128s = 0x0911,   // draft-reddy-tls-slhdsa-01
    slhdsa_sha2_128f = 0x0912,   // draft-reddy-tls-slhdsa-01
    slhdsa_sha2_192s = 0x0913,   // draft-reddy-tls-slhdsa-01
    slhdsa_sha2_192f = 0x0914,   // draft-reddy-tls-slhdsa-01
    slhdsa_sha2_256s = 0x0915,   // draft-reddy-tls-slhdsa-01
    slhdsa_sha2_256f = 0x0916,   // draft-reddy-tls-slhdsa-01
    slhdsa_shake_128s = 0x0917,  // draft-reddy-tls-slhdsa-01
    slhdsa_shake_128f = 0x0918,  // draft-reddy-tls-slhdsa-01
    slhdsa_shake_192s = 0x0919,  // draft-reddy-tls-slhdsa-01
    slhdsa_shake_192f = 0x091A,  // draft-reddy-tls-slhdsa-01
    slhdsa_shake_256s = 0x091B,  // draft-reddy-tls-slhdsa-01
    slhdsa_shake_256f = 0x091C,  // draft-reddy-tls-slhdsa-01
};

///////////////////////////////////////////////////////////////////////////
// key
///////////////////////////////////////////////////////////////////////////
/**
 * @brief get key
 * @sa crypto_key::get_key
 * @remarks
 * if there are both public_key | asn1public_key in the flag, asn1public_key has higher priority.
 * | key type   | public_key               | asn1public_key | private_key     |
 * | kty_oct    | N/A                      | N/A            | crypt_item_t::hmac_k     |
 * | kty_okp    | crypt_item_t::ec_x                | crypt_item_t::asn1der   | crypt_item_t::ec_d       |
 * | kty_mldsa  | crypt_item_t::ec_x                | crypt_item_t::asn1der   | crypt_item_t::ec_d       |
 * | kty_ec     | crypt_item_t::ec_pub_uncompressed | crypt_item_t::asn1der   | crypt_item_t::ec_d       |
 * | kty_rsa    | N/A                      | crypt_item_t::asn1der   | crypt_item_t::rsa_d      |
 * | kty_rsapss | N/A                      | crypt_item_t::asn1der   | crypt_item_t::rsa_d      |
 * | kty_dh     | crypt_item_t::dh_pub              | crypt_item_t::asn1der   | crypt_item_t::dh_priv    |
 * | kty_dsa    | N/A                      | crypt_item_t::asn1der   | crypt_item_t::dsa_x      |
 * | kty_mlkem  | TODO                     | TODO           | crypt_item_t::mlkem_priv |
 */
enum crypt_access_t {
    public_key = (1 << 0),      // simple and common representation
    private_key = (1 << 1),     //
    asn1public_key = (1 << 2),  // ASN.1 DER representation
};

// "ML-KEM-512"    1454    EVP_PKEY_ML_KEM_512
// "ML-KEM-768"    1455    EVP_PKEY_ML_KEM_768
// "ML-KEM-1024"   1456    EVP_PKEY_ML_KEM_1024

enum crypto_kty_t : uint16 {
    kty_unknown = 0,
    kty_oct = 1,          // NID_hmac
    kty_hmac = kty_oct,   // NID_hmac (synomym)
    kty_rsa = 2,          // NID_rsaEncryption, NID_rsa
    kty_ec = 3,           // NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1
    kty_okp = 4,          // NID_X25519,  NID_X448
    kty_eddsa = kty_okp,  // NID_ED25519, NID_ED448
    kty_dh = 5,           // NID_dhKeyAgreement
    kty_rsapss = 6,       // NID_rsassaPss
    kty_dsa = 7,          // NID_dsa
    kty_mlkem = 8,        // NID_ML_KEM_512, NID_ML_KEM_768, NID_ML_KEM_1024
    kty_mldsa = 9,        // NID_ML_DSA_44, NID_ML_DSA_65, NID_ML_DSA_87
    kty_slhdsa = 11,      // NIST FIPS 205

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

/**
 * RSA
 *   param
 *     n : RSA modulus (n)
 *     e : RSA public exponent (e)
 *     d : RSA private exponent (d)
 *     p : prime factor (p)
 *     q : q, "q", "prime factor (q)
 *     dp : CRT exponent (dp = d mod p-1)
 *     dq : CRT exponent (dq = d mod q-1)
 *     qi : CRT coefficient (qi = q^-1 mod p)
 * EC
 *   param
 *     x : EC public point x-coordinate
 *     y : EC public point y-coordinate
 *     d : EC private key
 *   signature
 *     r : signature component r
 *     s : signature component s
 * DH
 *   y = g^x mod p
 *     p : prime modulus
 *     q : subgroup order
 *     g : generator
 *     x : private key
 *     y : public key
 * DSA
 *   param
 *     p : prime modulus
 *     q : subgroup order
 *     g : generator
 *     x : private key
 *     y : public key
 *   signature
 *     k : nonce
 *     r : signature component r
 *     s : signature component s
 */

// (enum_type, enum_val, enum_text, desc)
#define CRYPT_ITEM_XGROUP_NULL(X) X(unknown, 0, "unknown", "")
#define CRYPT_ITEM_XGROUP_BINARY(X)                             \
    X(aad, 0x1, "aad", "additional authenticated data")         \
    X(cek, 0x2, "cek", "content encryption key")                \
    X(encryptedkey, 0x3, "encryptedkey", "encrypted CEK")       \
    X(iv, 0x4, "iv", "initialization vector")                   \
    X(nonce, 0x5, "nonce", "nonce")                             \
    X(ciphertext, 0x6, "ciphertext", "encrypted data")          \
    X(tag, 0x7, "tag", "authentication tag")                    \
    X(apu, 0x8, "apu", "agreement partyUInfo")                  \
    X(apv, 0x9, "apv", "agreement partyVInfo")                  \
    X(p2s, 0xa, "p2s", "PBES2 salt")                            \
    X(asn1der, 0xb, "der", "ASN.1 DER encoding")                \
    X(pubkey, 0xc, "pub", "public key")                         \
    X(privkey, 0xd, "priv", "private key")                      \
    X(k, 0xe, "k", "nonce or ephemeral secret")                 \
    X(n, 0xf, "n", "modulus")                                   \
    X(e, 0x10, "e", "public exponent")                          \
    X(d, 0x11, "d", "private exponent")                         \
    X(p, 0x12, "p", "prime modulus or prime factor")            \
    X(q, 0x13, "q", "subgroup order or prime factor")           \
    X(g, 0x14, "g", "generator")                                \
    X(dp, 0x15, "dp", "CRT exponent1")                          \
    X(dq, 0x16, "dq", "CRT exponent2")                          \
    X(qi, 0x17, "qi", "CRT coefficient")                        \
    X(x, 0x18, "x", "private value or x-coordinate")            \
    X(y, 0x19, "y", "public value or y-coordinate")             \
    X(uncompressed, 0x1a, "uncompressed", "uncompressed point") \
    X(r, 0x1b, "r", "signature component r")                    \
    X(s, 0x1c, "s", "signature component s")
/**
 * crv      const char*
 * header   const char*
 * kid      const char*
 * zip      const char*
 * epk      EVP_PKEY*
 * p2c      int32
 * ybit     bool
 */
#define CRYPT_ITEM_XGROUP_VARIANT(X)             \
    X(crv, 0x100, "crv", "crv")                  \
    X(header, 0x101, "header", "header")         \
    X(kid, 0x102, "kid", "kid")                  \
    X(zip, 0x103, "zip", "zip DEF")              \
    X(epk, 0x300, "epk", "ephemeral public key") \
    X(p2c, 0x301, "p2c", "PBES2 count")          \
    X(ybit, 0x302, "ybit", "EC compressed ybit")

#define CRYPT_ITEM_XGROUP_ALIAS_OCT(X) X(hmac_k, k, "k", "k")
#define CRYPT_ITEM_XGROUP_ALIAS_RSA(X)                       \
    X(rsa_n, n, "n", "RSA modulus (n)")                      \
    X(rsa_e, e, "e", "RSA public exponent (e)")              \
    X(rsa_d, d, "d", "RSA private exponent (d)")             \
    X(rsa_p, p, "p", "prime factor (p)")                     \
    X(rsa_q, q, "q", "prime factor (q)")                     \
    X(rsa_dp, dp, "dp", "CRT exponent (dp = d mod p-1)")     \
    X(rsa_dq, dq, "dq", "CRT exponent (dq = d mod q-1)")     \
    X(rsa_qi, qi, "qi", "CRT coefficient (qi = q^-1 mod p)") \
    X(rsa_pub, asn1der, "der", "RSA public key (ASN.1 DER)") \
    X(rsa_priv, d, "priv", "RSA private key")
#define CRYPT_ITEM_XGROUP_ALIAS_EC2(X)                                    \
    X(ec_x, x, "x", "EC public point x-coordinate (x)")                   \
    X(ec_y, y, "y", "EC public point y-coordinate (y)")                   \
    X(ec_d, d, "d", "EC private key (d)")                                 \
    X(ec_pub_uncompressed, uncompressed, "uncompressed", "EC public key") \
    X(ec_pub, ec_pub_uncompressed, "pub", "EC public key")                \
    X(ec_ybit, ybit, "ybit", "EC compressed point y-bit")                 \
    X(ec_crv, crv, "crv", "elliptic curve")
#define CRYPT_ITEM_XGROUP_ALIAS_OKP(X) \
    X(okp_x, x, "x", "OKP public (x)") \
    X(okp_d, d, "d", "OKP private key (d)")
#define CRYPT_ITEM_XGROUP_ALIAS_DH(X)                      \
    X(dh_p, p, "p", "DH prime modulus (p)")                \
    X(dh_q, q, "q", "DH subgroup order (q)")               \
    X(dh_g, g, "g", "DH generator (g)")                    \
    X(dh_y, y, "y", "DH public value (y = g^x mod p)")     \
    X(dh_x, x, "x", "DH private exponent (x)")             \
    X(dh_pub, asn1der, "pub", "DH public key (ASN.1 DER)") \
    X(dh_priv, privkey, "priv", "DH private key")
#define CRYPT_ITEM_XGROUP_ALIAS_DSA(X)                       \
    X(dsa_p, p, "p", "DSA prime modulus (p)")                \
    X(dsa_q, q, "q", "DSA subgroup order (q)")               \
    X(dsa_g, g, "g", "DSA generator (g)")                    \
    X(dsa_y, y, "y", "DSA public key (y)")                   \
    X(dsa_x, x, "x", "DSA private key (x)")                  \
    X(dsa_pub, asn1der, "der", "DSA public key (ASN.1 DER)") \
    X(dsa_priv, x, "priv", "DSA private key")
#define CRYPT_ITEM_XGROUP_ALIAS_MLKEM(X)      \
    X(mlkem_pub, pubkey, "pub", "public key") \
    X(mlkem_priv, privkey, "priv", "private key")
#define CRYPT_ITEM_XGROUP_ALIAS_MLDSA(X)      \
    X(mldsa_pub, pubkey, "pub", "public key") \
    X(mldsa_priv, privkey, "priv", "private key")
#define CRYPT_ITEM_XGROUP_ALIAS_SLHDSA(X)      \
    X(slhdsa_pub, pubkey, "pub", "public key") \
    X(slhdsa_priv, privkey, "priv", "private key")

enum class crypt_item_t : uint16 {
#define EXPAND_CRYPTITEM_ENUM(enum_type, enum_val, enum_text, desc) enum_type = enum_val,
    CRYPT_ITEM_XGROUP_NULL(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_BINARY(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_VARIANT(EXPAND_CRYPTITEM_ENUM)
        CRYPT_ITEM_XGROUP_ALIAS_OCT(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_ALIAS_RSA(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_ALIAS_EC2(EXPAND_CRYPTITEM_ENUM)
            CRYPT_ITEM_XGROUP_ALIAS_OKP(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_ALIAS_DH(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_ALIAS_DSA(EXPAND_CRYPTITEM_ENUM)
                CRYPT_ITEM_XGROUP_ALIAS_MLKEM(EXPAND_CRYPTITEM_ENUM) CRYPT_ITEM_XGROUP_ALIAS_MLDSA(EXPAND_CRYPTITEM_ENUM)
                    CRYPT_ITEM_XGROUP_ALIAS_SLHDSA(EXPAND_CRYPTITEM_ENUM)
#undef EXPAND_CRYPTITEM_ENUM
};

///////////////////////////////////////////////////////////////////////////
// TLS
///////////////////////////////////////////////////////////////////////////

// TLS key exchange
enum class keyexchange_t {
    unknown = 0,
    rsa = 1,           // Rivest Shamir Adleman algorithm (RSA)
    dh = 2,            // Diffie-Hellman (DH)
    dhe = 3,           // Diffie-Hellman Ephemeral (DHE)
    krb5 = 4,          // Kerberos 5 (KRB5)
    psk = 5,           // Pre-Shared Key (PSK)
    ecdh = 6,          // Elliptic Curve Diffie-Hellman (ECDH)
    ecdhe = 7,         // Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
    srp = 8,           // Secure Remote Password (SRP)
    eccpwd = 9,        // ECCPWD
    gost = 10,         // Russian cryptographic standard algorithms
    rsa_export = 11,   // TLS 1.0
    dss_export = 12,   // TLS 1.0
    anon_export = 13,  // TLS 1.0
    krb5_export = 14,  // TLS 1.0
    mlkem = 15,        // MLKEM
};

// TLS authentication
enum class auth_t {
    unknown = 0,
    dss = 1,       // Digital Signature Standard (DSS)
    rsa = 2,       // Rivest Shamir Adleman algorithm (RSA)
    anon = 3,      // Anonymous (anon)
    krb5 = 4,      // Kerberos 5 (KRB5)
    psk = 5,       // Pre-Shared Key (PSK)
    ecdsa = 6,     // Elliptic Curve Digital Signature Algorithm (ECDSA)
    sha1 = 7,      // Secure Hash Algorithm 1 with Rivest Shamir Adleman algorithm (SHA RSA)
    sha2_256 = 8,  // SHA256
    sha2_384 = 9,  // SHA384
    eccpwd = 10,   // ECCPWD
    gost = 11,     // GOST R 34.10-2012 Digital Signature Algorithm (GOSTR341012)
};

///////////////////////////////////////////////////////////////////////////
// JOSE
///////////////////////////////////////////////////////////////////////////
enum class jwa_group_t {
    rsa = 1,
    aeskw = 2,
    dir = 3,
    ecdh = 4,
    ecdh_aeskw = 5,
    aesgcmkw = 6,
    pbes_hs_aeskw = 7,
};

/**
 * @brief Cryptographic Algorithms for Key Management
 */
enum class jwa_t {
    unknown = 0,
    rsa_1_5 = 1,              // RSA1_5
    rsa_oaep = 2,             // RSA-OAEP
    rsa_oaep_256 = 3,         // RSA-OAEP-256
    a128kw = 4,               // A128KW
    a192kw = 5,               // A192KW
    a256kw = 6,               // A256KW
    dir = 7,                  // dir
    ecdh_es = 8,              // ECDH-ES
    ecdh_es_a128kw = 9,       // ECDH-ES+A128KW
    ecdh_es_a192kw = 10,      // ECDH-ES+A192KW
    ecdh_es_a256kw = 11,      // ECDH-ES+A256KW
    a128gcmkw = 12,           // A128GCMKW
    a192gcmkw = 13,           // A192GCMKW
    a256gcmkw = 14,           // A256GCMKW
    pbes2_hs256_a128kw = 15,  // PBES2-HS256+A128KW
    pbes2_hs384_a192kw = 16,  // PBES2-HS384+A192KW
    pbes2_hs512_a256kw = 17,  // PBES2-HS512+A256KW
};

enum class jwe_group_t {
    aescbc_hs = 1,
    aesgcm = 2,
};

/**
 * @brief Cryptographic Algorithms for Content Encryption
 */
enum class jwe_t {
    unknown = 0,
    a128cbc_hs256 = 1,  // A128CBC-HS256
    a192cbc_hs384 = 2,  // A192CBC-HS384
    a256cbc_hs512 = 3,  // A256CBC-HS512
    a128gcm = 4,        // A128GCM
    a192gcm = 5,        // A192GCM
    a256gcm = 6,        // A256GCM
};

enum class jws_group_t : uint8 {
    unknown = 0,
    hmac = t_underlying(sig_category_t::hmac),                    // HS256, HS384, HS512
    rsassa_pkcs15 = t_underlying(sig_category_t::rsassa_pkcs15),  // RS256, RS384, RS512
    ecdsa = t_underlying(sig_category_t::ecdsa),                  // ES256, ES384, ES512
    rsassa_pss = t_underlying(sig_category_t::rsassa_pss),        // PS256, PS384, PS512
    eddsa = t_underlying(sig_category_t::eddsa),                  // EdDSA
    mldsa = t_underlying(sig_category_t::mldsa),                  // MLDSA
    slhdsa = t_underlying(sig_category_t::slhdsa),                // SLH-DSA
};

/**
 * @brief Cryptographic Algorithms for Digital Signatures and MACs
 * RFC 7515 JSON Web Signature (JWS)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 */
enum class jws_t : uint16 {
    unknown = 0,
    hs256 = t_underlying(signature_t::hs256),
    hs384 = t_underlying(signature_t::hs384),
    hs512 = t_underlying(signature_t::hs512),
    rs256 = t_underlying(signature_t::rs256),
    rs384 = t_underlying(signature_t::rs384),
    rs512 = t_underlying(signature_t::rs512),
    es256 = t_underlying(signature_t::es256),
    es384 = t_underlying(signature_t::es384),
    es512 = t_underlying(signature_t::es512),
    ps256 = t_underlying(signature_t::ps256),
    ps384 = t_underlying(signature_t::ps384),
    ps512 = t_underlying(signature_t::ps512),
    eddsa = t_underlying(signature_t::eddsa),
    mldsa44 = t_underlying(signature_t::mldsa44),
    mldsa65 = t_underlying(signature_t::mldsa65),
    mldsa87 = t_underlying(signature_t::mldsa87),
};

///////////////////////////////////////////////////////////////////////////
// COSE
///////////////////////////////////////////////////////////////////////////
// https://www.iana.org/assignments/cose/cose.xhtml
enum cose_key_t {
    // COSE Header Parameters

    reserved = 0,

    // RFC 8152 Table 2: Common Header Parameters
    // RFC 8152 Table 3: Common Header Parameters
    alg = 1,           // int / tstr
    crit = 2,          // [+ label]
    content_type = 3,  // tstr / uint
    kid = 4,           // bstr
    iv = 5,            // bstr
    partial_iv = 6,    // bstr

    counter_sig = 7,  // COSE_Signature / [+ COSE_Signature]

    // RFC 8152 Table 27: Header Parameter for CounterSignature0
    counter_sig0 = 9,  // bstr
    kid_context = 10,  // bstr

    // RFC 9338 Table 1: Common Header Parameters
    // RFC 9338 Table 2: New Common Header Parameters
    counter_sig_v2 = 11,   // COSE_CounterSignature / [+COSE_CounterSignature]
    counter_sig0_v2 = 12,  // COSE_CounterSignature0

    // kccs = 14,        // map
    // cwt_claims = 15,  // map
    // typ = 16,         // uint / tstr
    // sd_claims = 17,   // [+bstr]
    // c5t = 22,         // COSE_CertHash
    // c5u = 23,         // url
    // c5b = 24,         // COSE_C509
    // c5c = 25,         // COSE_C509

    // RFC 9360 Table 1: X.509 COSE Header Parameters
    x5bag = 32,
    x5chain = 33,
    x5t = 34,
    x5u = 35,

    // sd_alg = 170,                    // int
    // sd_aead_encrypted_claims = 171,  // [+[bstr,bstr,bstr]]
    // sd_aead = 172,                   // uint .size 2

    // RFC 8152 Table 19: ECDH Algorithm Parameters
    // RFC 9053 Table 15: ECDH Algorithm Parameters
    epk = -1,
    ephemeral_key = epk,
    static_key = -2,
    static_key_id = -3,

    // RFC 8152 Table 13: HKDF Algorithm Parameters
    // RFC 9053 Table 9: HKDF Algorithm Parameters
    salt = -20,

    // RFC 8152 Table 14: Context Algorithm Parameters
    // RFC 9053 Table 10: Context Algorithm Parameters
    cose_partyu_id = -21,
    cose_partyu_nonce = -22,
    cose_partyu_other = -23,
    cose_partyv_id = -24,
    cose_partyv_nonce = -25,
    cose_partyv_other = -26,

    // RFC 9360 Table 2: Static ECDH Algorithm Values
    x5t_sender = -27,
    x5u_sender = -28,
    x5chain_sender = -29,
};
/**
 * https://www.iana.org/assignments/cose/cose.xhtml
 *
 *  cose key common parameters
 *  cose key type parameter
 */
enum cose_key_lable_t {
    // RFC 8152 Table 3: Key Map Labels
    // RFC 8152 Table 4: Key Map Labels
    cose_lable_kty = 1,
    cose_lable_kid = 2,
    cose_lable_alg = 3,
    cose_lable_keyops = 4,
    cose_lable_base_iv = 5,

    // COSE Key Type Parameters

    // RFC 8152 Table 23: EC Key Parameters
    // RFC 9053 Table 19: EC Key Parameters
    // cose_kty_t::ec2(2)
    cose_ec_crv = -1,
    cose_ec_x = -2,
    cose_ec_y = -3,
    cose_ec_d = -4,

    // RFC 8152 Table 24: Octet Key Pair Parameters
    // RFC 9053 Table 20: Octet Key Pair Parameters
    // cose_kty_t::okp(1)
    cose_okp_crv = -1,
    cose_okp_x = -2,
    cose_okp_d = -4,

    // RFC 8152 Table 25: Symmetric Key Parameters
    // RFC 9053 Table 21: Symmetric Key Parameters
    // cose_kty_t::symm(4)
    cose_symm_k = -1,

    // RSA 8230 Table 4: RSA Key Parameters
    // cose_kty_t::rsa(3)
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

    // cose_kty_t::hss_lms(5)

    // cose_kty_t::walnutdsa(6)

    // cose_kty_t::cose_kry_akp(7)
    cose_pub = -1,
    cose_priv = -2,
};

/**
 * @brief   cose key types
 *          https://www.iana.org/assignments/cose
 */
enum class cose_kty_t {
    // RFC 8152 Table 21: Key Type Values
    // RFC 9053 Table 17: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    unknown = 0,
    okp = 1,
    ec2 = 2,
    symm = 4,

    // RFC 8230 Table 3: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    rsa = 3,

    // RFC 9053 Table 22: Key Type Capabilities
    hss_lms = 5,
    walnutdsa = 6,
    // https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
    akp = 7,
};
enum class cose_keyop_t {
    // RFC 8152 Table 4: Key Operation Values
    // RFC 8152 Table 5: Key Operation Values
    sign = 1,
    verify = 2,
    encrypt = 3,
    decrypt = 4,
    wrap = 5,
    unwrap = 6,
    derive_key = 7,
    derive_bits = 8,
    mac_create = 9,
    mac_verify = 10,
};

/**
 * @brief   crypto_key::generate_cose
 *          https://www.iana.org/assignments/cose/cose.xhtml
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
    cose_ec_brainpoolp256r1 = 256,
    cose_ec_brainpoolp320r1 = 257,
    cose_ec_brainpoolp384r1 = 258,
    cose_ec_brainpoolp512r1 = 259,
};

enum class crypt_category_t {
    not_classified = 0,
    unknown = not_classified,
    crypt = 1,
    mac = 2,
    sign = 3,
    hash = 4,
    keydistribution = 5,
};

enum class cose_group_t {
    // RFC 8152 8. Signature Algorithms
    //   8.1.  ECDSA
    //   Table 5, ES256, ES284, ES512
    sign_ecdsa = 1,
    // RFC 8152 8. Signature Algorithms
    //   8.2.  Edwards-Curve Digital Signature Algorithms (EdDSAs)
    //   Table 6, EdDSA
    sign_eddsa = 2,
    // RFC 8152 9. Message Authentication Code (MAC) Algorithms
    //   9.1.  Hash-Based Message Authentication Codes (HMACs)
    //   Table 7, HMAC 256/64, HMAC 256/256, HMAC 384/384, HMAC 512/512
    mac_hmac = 3,
    // RFC 8152 9. Message Authentication Code (MAC) Algorithms
    //   9.2.  AES Message Authentication Code (AES-CBC-MAC)
    //   Table 8, AES-MAC 128/64, AES-MAC 256/64, AES-MAC 128/128, AES-MAC 256/128
    mac_aes = 4,
    // RFC 8152 10. Content Encryption Algorithms
    //   10.1.  AES GCM
    //   Table 9, A128GCM, A192GCM, A256GCM
    enc_aesgcm = 5,
    // RFC 8152 10. Content Encryption Algorithms
    //   10.2.  AES CCM
    //   Table 10, AES-CCM-16-64-128, ...
    enc_aesccm = 6,
    // RFC 8152 10. Content Encryption Algorithms
    //   10.3.  ChaCha20 and Poly1305
    //   Table 11, ChaCha20/Poly1305
    enc_chacha20_poly1305 = 7,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.1. Direct Encryption
    //   12.1.1.  Direct Key
    //   Table 15, direct
    key_direct = 8,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.1. Direct Encryption
    //   12.1.2.  Direct Key with KDF
    //   Table 16, direct+HKDF-SHA-256, direct+HKDF-SHA-512
    key_hkdf_hmac = 9,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.1. Direct Encryption
    //   12.1.2.  Direct Key with KDF
    //   Table 16,  direct+HKDF-AES-128, direct+HKDF-AES-256
    key_hkdf_aes = 10,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.2. Key Wrap
    //   12.2.1.  AES Key Wrap
    //   Table 17, A128KW, A192KW, A256KW
    key_aeskw = 11,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.4. Direct Key Agreement
    //   12.4.1.  ECDH
    //   Table 18 ECDH-ES+HKDF-256, ECDH-ES+HKDF-512, ECDH-SS+HKDF-256, ECDH-SS+HKDF-512
    key_ecdhes_hmac = 12,
    key_ecdhss_hmac = 13,
    // RFC 8152 12. Content Key Distribution Methods
    //   12.5. Key Agreement with Key Wrap
    //   12.5.1.  ECDH
    //   Table 20 ECDH-ES+A128KW,ECDH-ES+A192KW, ECDH-ES+A256KW, ECDH-SS+A128KW,ECDH-SS+A192KW, ECDH-SS+A256KW
    key_ecdhes_aeskw = 14,
    key_ecdhss_aeskw = 15,
    // RFC 8230 2.  RSASSA-PSS Signature Algorithm
    //   Table 1, PS256, PS384, PS512
    sign_rsassa_pss = 16,
    // RFC 8230 3.  RSAES-OAEP Key Encryption Algorithm
    //   Table 2, RSAES-OAEP w/ SHA-1, RSAES-OAEP w/ SHA-256, RSAES-OAEP w/ SHA-512
    key_rsa_oaep = 17,
    // RFC 8812 2.  RSASSA-PKCS1-v1_5 Signature Algorithm
    //   Table 1, RS256, RS384, RS512, RS1
    sign_rsassa_pkcs15 = 18,
    // RFC 9053 10.  IANA Considerations
    //   10.2.  Changes to the "COSE Algorithms" Registry
    //   Table 23, IV-GENERATION
    iv_generate = 19,
    // RFC 9054 3.  Hash Algorithm Identifiers
    //   Table 1, SHA-1
    //   Table 2, SHA-256/64, SHA-256, SHA-384, SHA-512, SHA-512/256
    hash = 20,
    sign_mldsa = 21,
};
/**
 * @breif   cose algorithms
 *          https://www.iana.org/assignments/cose/cose.xhtml
 */
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

    // https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
    cose_mldsa44 = -48,
    cose_mldsa65 = -49,
    cose_mldsa87 = -50,

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

    cose_esb512 = -268,  // ECDSA using BrainpoolP512r1 curve and SHA-512
    cose_esb384 = -267,  // ECDSA using BrainpoolP384r1 curve and SHA-384
    cose_esb320 = -266,  // ECDSA using BrainpoolP320r1 curve and SHA-384
    cose_esb256 = -265,  // ECDSA using BrainpoolP256r1 curve and SHA-256

    cose_kt256 = -264,          // KT256 XOF
    cose_kt128 = -263,          // KT128 XOF
    cose_turboshake256 = -262,  // KT256 XOF
    cose_turboshake128 = -261,  // KT128 XOF
    cose_walnutdsa = -260,

    cose_ed448 = -53,   // EdDSA using the Ed448 parameter set in Section 5.2 of [RFC8032
    cose_esp512 = -52,  // ECDSA using P-521 curve and SHA-512
    cose_esp384 = -51,  // ECDSA using P-384 curve and SHA-384

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
    cose_hint_kty_mldsa = 1 << 17,
};

/**
 *  aabbccdd
 *  \ \ \ \- mode
 *   \ \ \-- algorithm
 *    \ \--- hint
 *     \---- category
 */

constexpr uint32 make_cryptoscheme(crypt_algorithm_t c, crypt_mode_t m) { return static_cast<uint32>((t_underlying(c) << 8) | t_underlying(m)); }
constexpr uint32 make_cryptoscheme(uint32 d, crypt_algorithm_t c, crypt_mode_t m) {
    return static_cast<uint32>((d & 0xffff0000) | (t_underlying(c) << 8) | t_underlying(m));
}

enum class crypto_scheme_t : uint32 {
    unknown = 0,

    aes_128_cbc = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::cbc),
    aes_128_cfb = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::cfb),
    aes_128_cfb1 = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::cfb1),
    aes_128_cfb8 = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::cfb8),
    aes_128_ctr = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::ctr),
    aes_128_ecb = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::ecb),
    aes_128_ofb = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::ofb),
    aes_128_wrap = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::wrap),
    aes_192_cbc = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::cbc),
    aes_192_cfb = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::cfb),
    aes_192_cfb1 = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::cfb1),
    aes_192_cfb8 = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::cfb8),
    aes_192_ctr = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::ctr),
    aes_192_ecb = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::ecb),
    aes_192_ofb = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::ofb),
    aes_192_wrap = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::wrap),
    aes_256_cbc = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::cbc),
    aes_256_cfb = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::cfb),
    aes_256_cfb1 = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::cfb1),
    aes_256_cfb8 = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::cfb8),
    aes_256_ctr = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::ctr),
    aes_256_ecb = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::ecb),
    aes_256_ofb = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::ofb),
    aes_256_wrap = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::wrap),

    aria_128_cbc = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::cbc),
    aria_128_cfb = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::cfb),
    aria_128_cfb1 = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::cfb1),
    aria_128_cfb8 = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::cfb8),
    aria_128_ctr = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::ctr),
    aria_128_ecb = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::ecb),
    aria_128_ofb = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::ofb),
    aria_192_cbc = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::cbc),
    aria_192_cfb = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::cfb),
    aria_192_cfb1 = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::cfb1),
    aria_192_cfb8 = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::cfb8),
    aria_192_ctr = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::ctr),
    aria_192_ecb = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::ecb),
    aria_192_ofb = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::ofb),
    aria_256_cbc = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::cbc),
    aria_256_cfb = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::cfb),
    aria_256_cfb1 = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::cfb1),
    aria_256_cfb8 = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::cfb8),
    aria_256_ctr = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::ctr),
    aria_256_ecb = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::ecb),
    aria_256_ofb = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::ofb),

    bf_cbc = make_cryptoscheme(crypt_algorithm_t::blowfish, crypt_mode_t::cbc),
    bf_cfb = make_cryptoscheme(crypt_algorithm_t::blowfish, crypt_mode_t::cfb),
    bf_ecb = make_cryptoscheme(crypt_algorithm_t::blowfish, crypt_mode_t::ecb),
    bf_ofb = make_cryptoscheme(crypt_algorithm_t::blowfish, crypt_mode_t::ofb),

    camellia_128_cbc = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::cbc),
    camellia_128_cfb = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::cfb),
    camellia_128_cfb1 = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::cfb1),
    camellia_128_cfb8 = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::cfb8),
    camellia_128_ctr = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::ctr),
    camellia_128_ecb = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::ecb),
    camellia_128_ofb = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::ofb),
    camellia_192_cbc = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::cbc),
    camellia_192_cfb = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::cfb),
    camellia_192_cfb1 = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::cfb1),
    camellia_192_cfb8 = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::cfb8),
    camellia_192_ctr = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::ctr),
    camellia_192_ecb = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::ecb),
    camellia_192_ofb = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::ofb),
    camellia_256_cbc = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::cbc),
    camellia_256_cfb = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::cfb),
    camellia_256_cfb1 = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::cfb1),
    camellia_256_cfb8 = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::cfb8),
    camellia_256_ctr = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::ctr),
    camellia_256_ecb = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::ecb),
    camellia_256_ofb = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::ofb),

    chacha20 = make_cryptoscheme(crypt_algorithm_t::chacha20, crypt_mode_t::unknown),
    chacha20_poly1305 = make_cryptoscheme(crypt_algorithm_t::chacha20, crypt_mode_t::poly1305),

    cast5_cbc = make_cryptoscheme(crypt_algorithm_t::cast, crypt_mode_t::cbc),
    cast5_cfb = make_cryptoscheme(crypt_algorithm_t::cast, crypt_mode_t::cfb),
    cast5_ecb = make_cryptoscheme(crypt_algorithm_t::cast, crypt_mode_t::ecb),
    cast5_ofb = make_cryptoscheme(crypt_algorithm_t::cast, crypt_mode_t::ofb),
    idea_cbc = make_cryptoscheme(crypt_algorithm_t::idea, crypt_mode_t::cbc),
    idea_cfb = make_cryptoscheme(crypt_algorithm_t::idea, crypt_mode_t::cfb),
    idea_ecb = make_cryptoscheme(crypt_algorithm_t::idea, crypt_mode_t::ecb),
    idea_ofb = make_cryptoscheme(crypt_algorithm_t::idea, crypt_mode_t::ofb),
    rc2_cbc = make_cryptoscheme(crypt_algorithm_t::rc2, crypt_mode_t::cbc),
    rc2_cfb = make_cryptoscheme(crypt_algorithm_t::rc2, crypt_mode_t::cfb),
    rc2_ecb = make_cryptoscheme(crypt_algorithm_t::rc2, crypt_mode_t::ecb),
    rc2_ofb = make_cryptoscheme(crypt_algorithm_t::rc2, crypt_mode_t::ofb),
    rc5_cbc = make_cryptoscheme(crypt_algorithm_t::rc5, crypt_mode_t::cbc),
    rc5_cfb = make_cryptoscheme(crypt_algorithm_t::rc5, crypt_mode_t::cfb),
    rc5_ecb = make_cryptoscheme(crypt_algorithm_t::rc5, crypt_mode_t::ecb),
    rc5_ofb = make_cryptoscheme(crypt_algorithm_t::rc5, crypt_mode_t::ofb),
    sm4_cbc = make_cryptoscheme(crypt_algorithm_t::sm4, crypt_mode_t::cbc),
    sm4_cfb = make_cryptoscheme(crypt_algorithm_t::sm4, crypt_mode_t::cfb),
    sm4_ecb = make_cryptoscheme(crypt_algorithm_t::sm4, crypt_mode_t::ecb),
    sm4_ofb = make_cryptoscheme(crypt_algorithm_t::sm4, crypt_mode_t::ofb),
    sm4_ctr = make_cryptoscheme(crypt_algorithm_t::sm4, crypt_mode_t::ctr),
    seed_cbc = make_cryptoscheme(crypt_algorithm_t::seed, crypt_mode_t::cbc),
    seed_cfb = make_cryptoscheme(crypt_algorithm_t::seed, crypt_mode_t::cfb),
    seed_ecb = make_cryptoscheme(crypt_algorithm_t::seed, crypt_mode_t::ecb),
    seed_ofb = make_cryptoscheme(crypt_algorithm_t::seed, crypt_mode_t::ofb),
    rc4 = make_cryptoscheme(crypt_algorithm_t::rc4, crypt_mode_t::unknown),

    aes_128_ccm = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::ccm),
    aes_128_gcm = make_cryptoscheme(crypt_algorithm_t::aes128, crypt_mode_t::gcm),
    aes_192_ccm = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::ccm),
    aes_192_gcm = make_cryptoscheme(crypt_algorithm_t::aes192, crypt_mode_t::gcm),
    aes_256_ccm = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::ccm),
    aes_256_gcm = make_cryptoscheme(crypt_algorithm_t::aes256, crypt_mode_t::gcm),
    aria_128_ccm = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::ccm),
    aria_128_gcm = make_cryptoscheme(crypt_algorithm_t::aria128, crypt_mode_t::gcm),
    aria_192_ccm = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::ccm),
    aria_192_gcm = make_cryptoscheme(crypt_algorithm_t::aria192, crypt_mode_t::gcm),
    aria_256_ccm = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::ccm),
    aria_256_gcm = make_cryptoscheme(crypt_algorithm_t::aria256, crypt_mode_t::gcm),
    camellia_128_gcm = make_cryptoscheme(crypt_algorithm_t::camellia128, crypt_mode_t::gcm),
    camellia_192_gcm = make_cryptoscheme(crypt_algorithm_t::camellia192, crypt_mode_t::gcm),
    camellia_256_gcm = make_cryptoscheme(crypt_algorithm_t::camellia256, crypt_mode_t::gcm),

    /**
     * CCM, GCM
     *   SET_L=3, SET_IVLEN=15-L=12, AEAD_SET_TAG=16
     * CCM8
     *   SET_L=3, SET_IVLEN=15-L=12, AEAD_SET_TAG=8
     */
    tls_aes_128_ccm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aes128, crypt_mode_t::ccm),
    tls_aes_256_ccm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aes256, crypt_mode_t::ccm),
    tls_aes_128_ccm_8 = make_cryptoscheme((CRYPTO_SCHEME_CATEGORY_TLS | CRYPTO_SCHEME_HINT_CCM8), crypt_algorithm_t::aes128, crypt_mode_t::ccm),
    tls_aes_256_ccm_8 = make_cryptoscheme((CRYPTO_SCHEME_CATEGORY_TLS | CRYPTO_SCHEME_HINT_CCM8), crypt_algorithm_t::aes256, crypt_mode_t::ccm),
    tls_aes_128_gcm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aes128, crypt_mode_t::gcm),
    tls_aes_256_gcm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aes256, crypt_mode_t::gcm),
    tls_chacha20_poly1305 = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::chacha20, crypt_mode_t::poly1305),
    tls_aria_128_ccm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aria128, crypt_mode_t::ccm),
    tls_aria_256_ccm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aria256, crypt_mode_t::ccm),
    tls_aria_128_gcm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aria128, crypt_mode_t::gcm),
    tls_aria_256_gcm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::aria256, crypt_mode_t::gcm),
    tls_camellia_128_gcm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::camellia128, crypt_mode_t::gcm),
    tls_camellia_256_gcm = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_TLS, crypt_algorithm_t::camellia256, crypt_mode_t::gcm),

    aead_aes_128_cbc_hmac_sha2 = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_CBCHMAC, crypt_algorithm_t::aes128, crypt_mode_t::cbc),
    aead_aes_192_cbc_hmac_sha2 = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_CBCHMAC, crypt_algorithm_t::aes192, crypt_mode_t::cbc),
    aead_aes_256_cbc_hmac_sha2 = make_cryptoscheme(CRYPTO_SCHEME_CATEGORY_CBCHMAC, crypt_algorithm_t::aes256, crypt_mode_t::cbc),
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
    crypto_scheme_t scheme;
    crypt_algorithm_t algorithm;
    crypt_mode_t mode;
    const char* fetchname;
    uint8 nsize;
    uint8 tsize;
} hint_cipher_t;
crypto_scheme_t typeof_sheme(const hint_cipher_t* hint);
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
    const char* fetchname;  // advisor->hintof_digest("sha256")
    uint16 digest_size;
    const char* altname;  // advisor->hintof_digest("sha2-256")
    const char* rfcname;  // IANA style, SHA-256, SHA-1
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
    signature_t sig;          // ex. signature_t::eddsa
    jws_t jws_type;           // ex. jws_t::eddsa
    jws_group_t group;        // ex. jws_group_t::eddsa
    sig_category_t category;  // ex. sig_category_t::eddsa
    cose_alg_t cosealg;       //
    crypto_kty_t kty;         // ex. kty_okp
    const char* jws_name;     // ex. "EdDSA"
    hash_algorithm_t alg;     // ex. hash_algorithm_t{}
    uint32 count;             // ex. 2
    uint32 nid[3];            // ex. NID_ED25519, NID_ED448
} hint_signature_t;

sig_category_t categoryof(const hint_signature_t* hint);
signature_t typeof_sig(const hint_signature_t* hint);
jws_t typeof_jws(const hint_signature_t* hint);
crypto_kty_t typeof_kty(const hint_signature_t* hint);
const char* nameof_jws(const hint_signature_t* hint);
hash_algorithm_t typeof_alg(const hint_signature_t* hint);

typedef struct _hint_sigscheme_t {
    tls_sigscheme_t scheme;
    uint16 spec;  // TLS version (0x304 TLS 1.3)
    uint8 flags;
    const char* name;
    sig_category_t category;
    signature_t sig;
    crypto_kty_t kty;
    uint32 nid;
    hash_algorithm_t dgst;
    struct {
        uint16 signature;
        uint16 privkey;
        uint16 pubkey;
    } size;
} hint_sigscheme_t;

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
 *              id          openssl nid             NID_X9_62_prime256v1
 *              nid         openssl nid             NID_X9_62_prime256v1
 *              cose_crv    cose curve              cose_ec_p256
 *              kty         key type                kty_ec
 *              use         usage(enc, sig)         use_any
 *              group       TLS supported group     0x0017
 *              oid         OID
 *              name        NIST
 *              name_x962        X9.62, X9.63
 *              name_sec        Standards for Efficient Cryptography (SEC)
 *              name_wtls
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
struct hint_curve_t {
    uint32 id;                 // openssl NID
    uint32 nid;                // id and nid can be different (nid_brainpoolp256r1tls13, NID_brainpoolP256r1)
    crypto_kty_t kty;          // kty_ec, kty_okp
    crypto_use_t use;          // use_any, use_enc, use_sig
    tls_group_t tlsgroup;      // TLS group
    cose_ec_curve_t cose_crv;  // COSE
    uint16 flags;              // ECDSA_SUPPORT_xxx
    uint8 keysize;             // key size (preserve leading zero), (keysize-2 .. keysize)
    uint8 category;            // see curve_category_t
    const char* oid;           // OID, https://neuromancer.sk/
    const char* name_nist;     // NIST (CURVE P-256, P-384, P-521, ...)
    const char* name_x962;     // X9.62, X9.63 (ansip384r1, ansip521r1, ...)
    const char* name_sec;      // Standards for Efficient Cryptography (SEC) (secp256r1, secp384r1, secp521r1, ...)
    const char* name_bp;       // brainpool
    const char* name_wtls;     // WAP-TLS
};

enum tls_resource_flag_t : uint8 {
    tls_flag_secure = (1 << 0),   // secure, recommended
    tls_flag_support = (1 << 1),  // support
    tls_flag_pqc = (1 << 2),      // Post-Quantum Cryptography
    tls_flag_hybrid = (1 << 3),   // hybrid
};

struct hint_group_item_t {
    crypto_kty_t kty;
    uint32 nid;
    uint16 keysize;
    uint16 capsulesize;
    tls_group_t group;
};

struct hint_group_t {
    tls_group_t group;
    keyexchange_t exch;  // keyexchange_t::ecdhe, keyexchange_t::mlkem
    uint8 flags;         // tls_resource_flag_t
    const char* name;
    hint_group_item_t first;
    hint_group_item_t second;  // hybrid
};

///////////////////////////////////////////////////////////////////////////
uint32 nidof(const hint_curve_t* hint);
cose_ec_curve_t coseof(const hint_curve_t* hint);
crypto_kty_t ktyof(const hint_curve_t* hint);
tls_group_t tlsgroupof(const hint_curve_t* hint);
uint8 keysizeof(const hint_curve_t* hint);
const char* oidof(const hint_curve_t* hint);
bool support(const hint_curve_t* hint, hash_algorithm_t alg);
bool support(const hint_curve_t* hint, const char* alg);
bool support(const hint_curve_t* hint, const std::string& alg);

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
enum jose_hint_type_t {
    jwa = 1,
    jwe = 2,
    // jws = 3,
};
struct hint_jose_encryption_t {
    const char* alg_name;
    jose_hint_type_t htype;
    union {
        struct {
            jwa_t type;         // type
            jwa_group_t group;  // group
        } alg;
        struct {
            jwe_t type;         // type
            jwe_group_t group;  // group
        } enc;
    } u;
    crypto_kty_t kty;  // crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec, crypto_kty_t::kty_oct
    crypto_kty_t alt;  // for example crypto_kty_t::kty_okp, if kt is crypto_kty_t::kty_ec
    crypt_enc_t enc;   // crypt_enc_t::rsa_1_5, crypt_enc_t::rsa_oaep, crypt_enc_t::rsa_oaep256

    crypt_algorithm_t crypt_alg;  // algorithm for keywrap or GCM
    crypt_mode_t crypt_mode;      // crypt_mode_t::wrap, crypt_mode_t::gcm
    int keysize;                  // 16, 24, 32
    hash_algorithm_t hash_alg;

    hint_jose_encryption_t(const char* name, jose_hint_type_t ht, jwa_t type, jwa_group_t group, crypto_kty_t kt, crypto_kty_t at, crypt_enc_t ce = crypt_enc_t{},
                           crypt_algorithm_t ca = {}, crypt_mode_t cm = {}, int ks = 0, hash_algorithm_t ha = {})
        : alg_name(name), htype(ht), kty(kt), alt(at), enc(ce), crypt_alg(ca), crypt_mode(cm), keysize(ks), hash_alg(ha) {
        u.alg.type = type;
        u.alg.group = group;
    }
    hint_jose_encryption_t(const char* name, jose_hint_type_t ht, jwe_t type, jwe_group_t group, crypto_kty_t kt, crypto_kty_t at, crypt_enc_t ce = crypt_enc_t{},
                           crypt_algorithm_t ca = {}, crypt_mode_t cm = {}, int ks = 0, hash_algorithm_t ha = {})
        : alg_name(name), htype(ht), kty(kt), alt(at), enc(ce), crypt_alg(ca), crypt_mode(cm), keysize(ks), hash_alg(ha) {
        u.enc.type = type;
        u.enc.group = group;
    }
};
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
    struct _keyinfo {
        uint16 nid;
        cose_ec_curve_t curve;
    } keyinfo;
    struct _dgst {
        const char* algname;
        uint16 dlen;
        uint16 klen;
    } dgst;
    struct _enc {
        const char* algname;
        uint16 ksize;
        uint16 tsize;
        uint16 nsize;
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

/**
 * nid (use openssl nid definition for convenience)
 *
 * #ifndef NID_ML_KEM_512
 * #define NID_ML_KEM_512 1454
 * #endif
 */
enum nid_t : uint32 {
    nid_rsa = 6,                      // EVP_PKEY_RSA, NID_rsaEncryption
    nid_rsa2 = 19,                    // EVP_PKEY_RSA2, NID_rsa
    nid_dh = 28,                      // NID_dhKeyAgreement (EVP_PKEY_DH)
    nid_dsa = 116,                    // NID_dsa
    nid_oct = 855,                    // EVP_PKEY_HMAC, NID_hmac
    nid_rsapss = 912,                 // EVP_PKEY_RSA_PSS, NID_rsassaPss
    nid_sha512_224 = 1094,            // NID_sha512_224 (openssl-3.0)
    nid_sha512_256 = 1095,            // NID_sha512_256 (openssl-3.0)
    nid_ffdhe2048 = 1126,             // NID_ffdhe2048
    nid_ffdhe3072 = 1127,             // NID_ffdhe3072
    nid_ffdhe4096 = 1128,             // NID_ffdhe4096
    nid_ffdhe6144 = 1129,             // NID_ffdhe6144
    nid_ffdhe8192 = 1130,             // NID_ffdhe8192
    nid_brainpoolp256r1tls13 = 1285,  // NID_brainpoolP256r1tls13 (openssl-3.2)
    nid_brainpoolp384r1tls13 = 1286,  // NID_brainpoolP384r1tls13 (openssl-3.2)
    nid_brainpoolp512r1tls13 = 1287,  // NID_brainpoolP512r1tls13 (openssl-3.2)
    nid_mlkem512 = 1454,              // NID_ML_KEM_512 (openssl-3.5)
    nid_mlkem768 = 1455,              // NID_ML_KEM_768 (openssl-3.5)
    nid_mlkem1024 = 1456,             // NID_ML_KEM_1024 (openssl-3.5)
    nid_ml_dsa_44 = 1457,             // NID_ML_DSA_44 (openssl-3.5)
    nid_ml_dsa_65 = 1458,             // NID_ML_DSA_65 (openssl-3.5)
    nid_ml_dsa_87 = 1459,             // NID_ML_DSA_87 (openssl-3.5)
    nid_slhdsa_sha2_128s = 1460,      // NID_SLH_DSA_SHA2_128s  RFC 9909 (openssl-3.5)
    nid_slhdsa_sha2_128f = 1461,      // NID_SLH_DSA_SHA2_128f  RFC 9909 (openssl-3.5)
    nid_slhdsa_sha2_192s = 1462,      // NID_SLH_DSA_SHA2_192s  RFC 9909 (openssl-3.5)
    nid_slhdsa_sha2_192f = 1463,      // NID_SLH_DSA_SHA2_192f  RFC 9909 (openssl-3.5)
    nid_slhdsa_sha2_256s = 1464,      // NID_SLH_DSA_SHA2_256s  RFC 9909 (openssl-3.5)
    nid_slhdsa_sha2_256f = 1465,      // NID_SLH_DSA_SHA2_256f  RFC 9909 (openssl-3.5)
    nid_slhdsa_shake_128s = 1466,     // NID_SLH_DSA_SHAKE_128s RFC 9909 (openssl-3.5)
    nid_slhdsa_shake_128f = 1467,     // NID_SLH_DSA_SHAKE_128f RFC 9909 (openssl-3.5)
    nid_slhdsa_shake_192s = 1468,     // NID_SLH_DSA_SHAKE_192s RFC 9909 (openssl-3.5)
    nid_slhdsa_shake_192f = 1469,     // NID_SLH_DSA_SHAKE_192f RFC 9909 (openssl-3.5)
    nid_slhdsa_shake_256s = 1470,     // NID_SLH_DSA_SHAKE_256s RFC 9909 (openssl-3.5)
    nid_slhdsa_shake_256f = 1471,     // NID_SLH_DSA_SHAKE_256f RFC 9909 (openssl-3.5)
};

/**
 * @sa  class crypto_cbc_hmac
 */
enum authenticated_encryption_flag_t : uint16 {
    tls_mac_then_encrypt = 0x0001,
    jose_encrypt_then_mac = 0x8001,
    tls_encrypt_then_mac = 0x8002,
};

///////////////////////////////////////////////////////////////////////////
// openssl-3.0 ENCODER
///////////////////////////////////////////////////////////////////////////

// openssl definitions
#define KEY_ENCODING_PEM 0x00000001
#define KEY_ENCODING_DER 0x00000002
#define KEY_ENCODING_RAW 0x00000003
#define KEY_ENCODING_FORMAT 0x000000ff
#define KEY_ENCODING_PRIV_ENCRYPTED 0xc0000000
#define KEY_ENCODING_PRIV 0x80000000
#define KEY_ENCODING_PUB 0x00000000

enum key_encoding_t : uint32 {
    key_encoding_priv_pem = KEY_ENCODING_PRIV | KEY_ENCODING_PEM,
    key_encoding_encrypted_priv_pem = KEY_ENCODING_PRIV_ENCRYPTED | KEY_ENCODING_PEM,
    key_encoding_pub_pem = KEY_ENCODING_PUB | KEY_ENCODING_PEM,
    key_encoding_priv_der = KEY_ENCODING_PRIV | KEY_ENCODING_DER,
    key_encoding_encrypted_priv_der = KEY_ENCODING_PRIV_ENCRYPTED | KEY_ENCODING_DER,
    key_encoding_pub_der = KEY_ENCODING_PUB | KEY_ENCODING_DER,
    key_encoding_priv_raw = KEY_ENCODING_PRIV | KEY_ENCODING_RAW,
    key_encoding_pub_raw = KEY_ENCODING_PUB | KEY_ENCODING_RAW,
};

struct key_encoding_params_t {
    int selection;
    const char* format;
    const char* structure;
    bool use_pass;
};

struct hint_advisor_t {
    crypto_kty_t kty = kty_unknown;
    uint32 nid = 0;
    const hint_kty_name_t* hint_kty = nullptr;
    const hint_blockcipher_t* hint_blockcipher = nullptr;
    const hint_cipher_t* hint_cipher = nullptr;
    const hint_digest_t* hint_digest = nullptr;
    const hint_curve_t* hint_curve = nullptr;
    const hint_sigscheme_t* hint_sigscheme = nullptr;
    const hint_jose_encryption_t* hint_jwa = nullptr;
    const hint_jose_encryption_t* hint_jwe = nullptr;
    const hint_signature_t* hint_jws = nullptr;
    const hint_group_t* hint_group = nullptr;

    hint_advisor_t() = default;
    hint_advisor_t(const hint_advisor_t&) = default;
    hint_advisor_t& operator=(const hint_advisor_t&) = default;

    void clear() {
        kty = kty_unknown;
        nid = 0;
        hint_kty = nullptr;
        hint_blockcipher = nullptr;
        hint_cipher = nullptr;
        hint_digest = nullptr;
        hint_curve = nullptr;
        hint_sigscheme = nullptr;
        hint_jwa = nullptr;
        hint_jwe = nullptr;
        hint_jws = nullptr;
        hint_group = nullptr;
    }
};

std::string namesof(const hint_advisor_t* hint);

}  // namespace crypto
}  // namespace hotplace

#endif
