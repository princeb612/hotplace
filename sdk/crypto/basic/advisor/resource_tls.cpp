/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <iostream>

namespace hotplace {
namespace crypto {

// avoid compile error
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#define tls_flag_support_pqc tls_flag_support
#else
#define tls_flag_support_pqc 0
#endif

const hint_group_t hint_groups[] = {
    // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
    // ffdhe2048~ffdhe8192

    // sa. const hint_curve_t hint_curves[]

    {
        tls_group_sect163k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect163k1",
        kty_ec,
        NID_sect163k1,
    },  // K-163, ansit163k1
    {
        tls_group_sect163r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect163r1",
        kty_ec,
        NID_sect163r1,
    },  // ansit163r1
    {
        tls_group_sect163r2,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect163r2",
        kty_ec,
        NID_sect163r2,
    },  // B-163, ansit163r2
    {
        tls_group_sect193r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect193r1",
        kty_ec,
        NID_sect193r1,
    },  // ansit193r1
    {
        tls_group_sect193r2,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect193r2",
        kty_ec,
        NID_sect193r2,
    },  // sect193r2
    {
        tls_group_sect233k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect233k1",
        kty_ec,
        NID_sect233k1,
    },  // K-233, ansit233k1
    {
        tls_group_sect233r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect233r1",
        kty_ec,
        NID_sect233r1,
    },  // B-233, ansit233r1
    {
        tls_group_sect239k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect239k1",
        kty_ec,
        NID_sect239k1,
    },  // ansit239k1
    {
        tls_group_sect283k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect283k1",
        kty_ec,
        NID_sect283k1,
    },  // K-283, ansit283k1
    {
        tls_group_sect283r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect283r1",
        kty_ec,
        NID_sect283r1,
    },  // B-283, ansit283r1
    {
        tls_group_sect409k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect409k1",
        kty_ec,
        NID_sect409k1,
    },  // K-409, ansit409k1
    {
        tls_group_sect409r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect409r1",
        kty_ec,
        NID_sect409r1,
    },  // B-409, ansit409r1
    {
        tls_group_sect571k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect571k1",
        kty_ec,
        NID_sect571k1,
    },  // K-571, ansit571k1
    {
        tls_group_sect571r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "sect571r1",
        kty_ec,
        NID_sect571r1,
    },  // B-571, ansit571r1
    {
        tls_group_secp160k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp160k1",
        kty_ec,
        NID_secp160k1,
    },  // ansip160k1
    {
        tls_group_secp160r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp160r1",
        kty_ec,
        NID_secp160r1,
    },  // ansip160r1
    {
        tls_group_secp160r2,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp160r2",
        kty_ec,
        NID_secp160r2,
    },  // ansip160r2
    {
        tls_group_secp192k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp192k1",
        kty_ec,
        NID_secp192k1,
    },  // ansip192k1
    {
        tls_group_secp192r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp192r1",
        kty_ec,
        NID_X9_62_prime192v1,
    },  // P-192, prime192v1
    {
        tls_group_secp224k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp224k1",
        kty_ec,
        NID_secp224k1,
    },  // ansip224k1
    {
        tls_group_secp224r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp224r1",
        kty_ec,
        NID_secp224r1,
    },  // ansip224r1
    {
        tls_group_secp256k1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp256k1",
        kty_ec,
        NID_secp256k1,
    },  // ansip256k1
    {
        tls_group_secp256r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp256r1",
        kty_ec,
        NID_X9_62_prime256v1,
    },  // P-256, prime256v1, RFC 8446 9.1 MUST
    {
        tls_group_secp384r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp384r1",
        kty_ec,
        NID_secp384r1,
    },  // P-384, ansip384r1
    {
        tls_group_secp521r1,
        keyexchange_ecdhe,
        tls_flag_support,
        "secp521r1",
        kty_ec,
        NID_secp521r1,
    },  // P-521, ansip521r1
    {
        tls_group_brainpoolP256r1,  //  RFC 7027
        keyexchange_ecdhe,
        tls_flag_support,
        "brainpoolP256r1",
        kty_ec,
        NID_brainpoolP256r1,
    },
    {
        tls_group_brainpoolP384r1,  //  RFC 7027
        keyexchange_ecdhe,
        tls_flag_support,
        "brainpoolP384r1",
        kty_ec,
        NID_brainpoolP384r1,
    },
    {
        tls_group_brainpoolP512r1,  //  RFC 7027
        keyexchange_ecdhe,
        tls_flag_support,
        "brainpoolP512r1",
        kty_ec,
        NID_brainpoolP512r1,
    },
    {
        tls_group_x25519,
        keyexchange_ecdhe,
        tls_flag_support,
        "x25519",
        kty_okp,
        NID_X25519,
    },  // RFC 8446 8446 9.1 MUST
    {
        tls_group_x448,
        keyexchange_ecdhe,
        tls_flag_support,
        "x448",
        kty_okp,
        NID_X448,
    },
    {
        tls_group_brainpoolP256r1tls13,  //  RFC 8734
        keyexchange_ecdhe,
        tls_flag_support,
        "brainpoolP256r1tls13",
        kty_ec,
        NID_brainpoolP256r1,
    },
    {
        tls_group_brainpoolP384r1tls13,  //  RFC 8734
        keyexchange_ecdhe,
        tls_flag_support,
        "brainpoolP384r1tls13",
        kty_ec,
        NID_brainpoolP384r1,
    },
    {
        tls_group_brainpoolP512r1tls13,  //  RFC 8734
        keyexchange_ecdhe,
        tls_flag_support,
        "brainpoolP512r1tls13",
        kty_ec,
        NID_brainpoolP512r1,
    },
    {
        tls_group_GC256A,
        keyexchange_unknown,
        0,
        "GC256A",
        kty_unknown,
        0,
    },
    {
        tls_group_GC256B,
        keyexchange_unknown,
        0,
        "GC256B",
        kty_unknown,
        0,
    },
    {
        tls_group_GC256C,
        keyexchange_unknown,
        0,
        "GC256C",
        kty_unknown,
        0,
    },
    {
        tls_group_GC256D,
        keyexchange_unknown,
        0,
        "GC256D",
        kty_unknown,
        0,
    },
    {
        tls_group_GC512A,
        keyexchange_unknown,
        0,
        "GC512A",
        kty_unknown,
        0,
    },
    {
        tls_group_GC512B,
        keyexchange_unknown,
        0,
        "GC512B",
        kty_unknown,
        0,
    },
    {
        tls_group_GC512C,
        keyexchange_unknown,
        0,
        "GC512C",
        kty_unknown,
        0,
    },
    {
        tls_group_curveSM2,
        keyexchange_unknown,
        0,
        "curveSM2",
        kty_unknown,
        0,
    },
    {
        tls_group_ffdhe2048,
        keyexchange_ecdhe,
        tls_flag_support,
        "ffdhe2048",
        kty_dh,
        NID_ffdhe2048,
    },
    {
        tls_group_ffdhe3072,
        keyexchange_ecdhe,
        tls_flag_support,
        "ffdhe3072",
        kty_dh,
        NID_ffdhe3072,
    },
    {
        tls_group_ffdhe4096,
        keyexchange_ecdhe,
        tls_flag_support,
        "ffdhe4096",
        kty_dh,
        NID_ffdhe4096,
    },
    {
        tls_group_ffdhe6144,
        keyexchange_ecdhe,
        tls_flag_support,
        "ffdhe6144",
        kty_dh,
        NID_ffdhe6144,
    },
    {
        tls_group_ffdhe8192,
        keyexchange_ecdhe,
        tls_flag_support,
        "ffdhe8192",
        kty_dh,
        NID_ffdhe8192,
    },
    {
        tls_group_mlkem512,
        keyexchange_mlkem,
        tls_flag_support_pqc | tls_flag_secure | tls_flag_pqc,
        "MLKEM512",
        kty_mlkem,
        nid_mlkem512,
        800,
        768,
    },
    {
        tls_group_mlkem768,
        keyexchange_mlkem,
        tls_flag_support_pqc | tls_flag_secure | tls_flag_pqc,
        "MLKEM768",
        kty_mlkem,
        nid_mlkem768,
        1184,
        1088,
    },
    {
        tls_group_mlkem1024,
        keyexchange_mlkem,
        tls_flag_support_pqc | tls_flag_secure | tls_flag_pqc,
        "MLKEM1024",
        kty_mlkem,
        nid_mlkem1024,
        1568,
        1568,
    },
    {
        tls_group_secp256r1mlkem768,
        keyexchange_mlkem,
        tls_flag_secure | tls_flag_pqc | tls_flag_hybrid,
        "SecP256r1MLKEM768",
        kty_mlkem,
        nid_mlkem768,
        1184,
        1088,
        kty_ec,
        NID_X9_62_prime256v1,
        65,
    },
    {
        tls_group_x25519mlkem768,
        keyexchange_mlkem,
        tls_flag_secure | tls_flag_pqc | tls_flag_hybrid,
        "X25519MLKEM768",
        kty_mlkem,
        nid_mlkem768,
        1184,
        1088,
        kty_okp,
        NID_X25519,
        32,
    },
    {
        tls_group_secp384r1mlkem1024,
        keyexchange_mlkem,
        tls_flag_secure | tls_flag_pqc | tls_flag_hybrid,
        "SecP384r1MLKEM1024",
        kty_mlkem,
        nid_mlkem1024,
        1568,
        1568,
        kty_ec,
        NID_secp384r1,
        97,
    },
    {
        0xff01,
        keyexchange_unknown,
        0,
        "arbitrary_explicit_prime_curves",
        kty_unknown,
        0,
    },
    {
        0xff02,
        keyexchange_unknown,
        0,
        "arbitrary_explicit_char2_curves",
        kty_unknown,
        0,
    },
};
const size_t sizeof_hint_groups = RTL_NUMBER_OF(hint_groups);

}  // namespace crypto
}  // namespace hotplace
