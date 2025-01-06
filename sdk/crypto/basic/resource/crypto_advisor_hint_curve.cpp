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

const hint_curve_t hint_curves[] = {
    // https://neuromancer.sk/std/secg/secp112r1
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls6
    {
        NID_secp112r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.6",
        nullptr,
        nullptr,
        "secp112r1",
        "wap-wsg-idm-ecid-wtls6",
    },
    // https://neuromancer.sk/std/secg/secp112r2
    {
        NID_secp112r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.7",
        nullptr,
        nullptr,
        "secp112r2",
    },
    // https://neuromancer.sk/std/secg/secp128r1
    {
        NID_secp128r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.28",
        nullptr,
        nullptr,
        "secp128r1",
    },
    // https://neuromancer.sk/std/secg/secp128r2
    {
        NID_secp128r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.29",
        nullptr,
        nullptr,
        "secp128r2",
    },
    // https://neuromancer.sk/std/x963/ansip160k1
    // https://neuromancer.sk/std/secg/secp160k1
    {
        NID_secp160k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x000f,
        "1.3.132.0.9",
        nullptr,
        "ansip160k1",
        "secp160k1",
    },
    // https://neuromancer.sk/std/x963/ansip160r1
    // https://neuromancer.sk/std/secg/secp160r1
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls7
    {
        NID_secp160r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0010,
        "1.3.132.0.8",
        nullptr,
        "ansip160r1",
        "secp160r1",
        "wap-wsg-idm-ecid-wtls7",
    },
    // https://neuromancer.sk/std/x963/ansip160r2
    // https://neuromancer.sk/std/secg/secp160r2
    {
        NID_secp160r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0011,
        "1.3.132.0.30",
        nullptr,
        "ansip160r2",
        "secp160r2",
    },
    // https://neuromancer.sk/std/x963/ansip192k1
    // https://neuromancer.sk/std/secg/secp192k1
    {
        NID_secp192k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0012,
        "1.3.132.0.31",
        nullptr,
        "ansip192k1",
        "secp192k1",
    },
    // https://neuromancer.sk/std/nist/P-192
    // https://neuromancer.sk/std/x962/prime192v1
    // https://neuromancer.sk/std/secg/secp192r1
    {
        NID_X9_62_prime192v1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0013,
        "1.2.840.10045.3.1.1",
        "P-192",
        "prime192v1",
        "secp192r1",
    },
    // https://neuromancer.sk/std/x963/ansip224k1
    // https://neuromancer.sk/std/secg/secp224k1
    {
        NID_secp224k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0014,
        "1.3.132.0.32",
        nullptr,
        "ansip224k1",
        "secp224k1",
    },
    // https://neuromancer.sk/std/nist/P-224
    // https://neuromancer.sk/std/x963/ansip224r1
    // https://neuromancer.sk/std/secg/secp224r1
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls12
    {
        NID_secp224r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0015,
        "1.3.132.0.33",
        "P-224",
        "ansip224r1",
        "secp224r1",
        "wap-wsg-idm-ecid-wtls12",
    },
    // https://neuromancer.sk/std/x963/ansip256k1
    // https://neuromancer.sk/std/secg/secp256k1
    {
        NID_secp256k1,
        cose_ec_curve_t::cose_ec_secp256k1,  // RFC8812 ES256K, "secp256k1"
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0016,
        "1.3.132.0.10",
        nullptr,
        "ansip256k1",
        "secp256k1",
    },
    // https://neuromancer.sk/std/nist/P-256
    // https://neuromancer.sk/std/x962/prime256v1
    // https://neuromancer.sk/std/secg/secp256r1
    {
        NID_X9_62_prime256v1,
        cose_ec_curve_t::cose_ec_p256,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0017,
        "1.2.840.10045.3.1.7",
        "P-256",
        "prime256v1",
        "secp256r1",
    },
    // https://neuromancer.sk/std/nist/P-384
    // https://neuromancer.sk/std/x963/ansip384r1
    // https://neuromancer.sk/std/secg/secp384r1
    {
        NID_secp384r1,
        cose_ec_curve_t::cose_ec_p384,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0018,
        "1.3.132.0.34",
        "P-384",
        "ansip384r1",
        "secp384r1",
    },
    // https://neuromancer.sk/std/nist/P-521
    // https://neuromancer.sk/std/x963/ansip521r1
    // https://neuromancer.sk/std/secg/secp521r1
    {
        NID_secp521r1,
        cose_ec_curve_t::cose_ec_p521,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0019,
        "1.3.132.0.35",
        "P-521",
        "ansip521r1",
        "secp521r1",
    },
    // https://neuromancer.sk/std/secg/sect113r1
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls4
    {
        NID_sect113r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.4",
        nullptr,
        nullptr,
        "sect113r1",
        "wap-wsg-idm-ecid-wtls4",
    },
    // https://neuromancer.sk/std/secg/sect113r2
    {
        NID_sect113r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.5",
        nullptr,
        nullptr,
        "sect113r2",
    },
    // https://neuromancer.sk/std/secg/sect131r1
    {
        NID_sect131r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.22",
        nullptr,
        nullptr,
        "sect131r1",
    },
    // https://neuromancer.sk/std/secg/sect131r2
    {
        NID_sect131r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.132.0.23",
        nullptr,
        nullptr,
        "sect131r2",
    },
    // https://neuromancer.sk/std/nist/K-163
    // https://neuromancer.sk/std/x963/ansit163k1
    // https://neuromancer.sk/std/secg/sect163k1/
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls3
    {
        NID_sect163k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0001,
        "1.3.132.0.1",
        "K-163",
        "ansit163k1",
        "sect163k1",
        "wap-wsg-idm-ecid-wtls3",
    },
    // https://neuromancer.sk/std/x963/ansit163r1
    // https://neuromancer.sk/std/secg/sect163r1
    {
        NID_sect163r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0002,
        "1.3.132.0.2",
        nullptr,
        "ansit163r1",
        "sect163r1",
    },
    // https://neuromancer.sk/std/nist/B-163
    // https://neuromancer.sk/std/x963/ansit163r2
    // https://neuromancer.sk/std/secg/sect163r2
    {
        NID_sect163r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0003,
        "1.3.132.0.15",
        "B-163",
        "ansit163r2",
        "sect163r2",
    },
    // https://neuromancer.sk/std/x963/ansit193r1
    // https://neuromancer.sk/std/secg/sect193r1
    {
        NID_sect193r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0004,
        "1.3.132.0.24",
        nullptr,
        "ansit193r1",
        "sect193r1",
    },
    // https://neuromancer.sk/std/x963/ansit193r2
    // https://neuromancer.sk/std/secg/sect193r2
    {
        NID_sect193r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0005,
        "1.3.132.0.25",
        nullptr,
        nullptr,
        "sect193r2",
    },
    // https://neuromancer.sk/std/nist/K-233
    // https://neuromancer.sk/std/x963/ansit233k1
    // https://neuromancer.sk/std/secg/sect233k1
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls10
    {
        NID_sect233k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0006,
        "1.3.132.0.26",
        "K-233",
        "ansit233k1",
        "sect233k1",
        "wap-wsg-idm-ecid-wtls10",
    },
    // https://neuromancer.sk/std/nist/B-233
    // https://neuromancer.sk/std/x963/ansit233r1
    // https://neuromancer.sk/std/secg/sect233r1
    // https://neuromancer.sk/std/wtls/wap-wsg-idm-ecid-wtls11
    {
        NID_sect233r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0007,
        "1.3.132.0.27",
        "B-233",
        "ansit233r1",
        "sect233r1",
        "wap-wsg-idm-ecid-wtls11",
    },
    // https://neuromancer.sk/std/x963/ansit239k1
    // https://neuromancer.sk/std/secg/sect239k1
    {
        NID_sect239k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0008,
        "1.3.132.0.3",
        nullptr,
        "ansit239k1",
        "sect239k1",
    },
    // https://neuromancer.sk/std/secg/sect283k1
    {
        NID_sect283k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0009,
        "1.3.132.0.16",
        "K-283",
        "ansit283k1",
        "sect283k1",
    },
    // https://neuromancer.sk/std/nist/B-283
    // https://neuromancer.sk/std/x963/ansit283r1
    // https://neuromancer.sk/std/secg/sect283r1
    {
        NID_sect283r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x000a,
        "1.3.132.0.17",
        "B-283",
        "ansit283r1",
        "sect283r1",
    },
    // https://neuromancer.sk/std/nist/K-409
    // https://neuromancer.sk/std/x963/ansit409k1
    // https://neuromancer.sk/std/secg/sect409k1
    {
        NID_sect409k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x000b,
        "1.3.132.0.36",
        "K-409",
        "ansit409k1",
        "sect409k1",
    },
    // https://neuromancer.sk/std/nist/B-409
    // https://neuromancer.sk/std/x963/ansit409r1
    // https://neuromancer.sk/std/secg/sect409r1
    {
        NID_sect409r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x000c,
        "1.3.132.0.37",
        "B-409",
        "ansit409r1",
        "sect409r1",
    },
    // https://neuromancer.sk/std/nist/K-571
    // https://neuromancer.sk/std/x963/ansit571k1
    // https://neuromancer.sk/std/secg/sect571k1
    {
        NID_sect571k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x000d,
        "1.3.132.0.38",
        "K-571",
        "ansit571k1",
        "sect571k1",
    },
    // https://neuromancer.sk/std/nist/B-571
    // https://neuromancer.sk/std/x963/ansit571r1
    // https://neuromancer.sk/std/secg/sect571r1
    {
        NID_sect571r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x000e,
        "1.3.132.0.39",
        "B-571",
        "ansit571r1",
        "sect571r1",
    },
    //
    {
        NID_X25519,
        cose_ec_curve_t::cose_ec_x25519,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_enc,
        0x001d,
        "1.3.101.110",  // RFC 8410
        "X25519",
    },
    //
    {
        NID_X448,
        cose_ec_curve_t::cose_ec_x448,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_enc,
        0x001e,
        "1.3.101.111",  // RFC 8410
        "X448",
    },
    //
    {
        NID_ED25519,
        cose_ec_curve_t::cose_ec_ed25519,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_sig,
        0x0000,
        "1.3.101.112",  // RFC 8410
        "Ed25519",
    },
    //
    {
        NID_ED448,
        cose_ec_curve_t::cose_ec_ed448,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_sig,
        0x0000,
        "1.3.101.113",  // RFC 8410
        "Ed448",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP160r1
    {
        NID_brainpoolP160r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.1",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP160r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP160t1
    {
        NID_brainpoolP160t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.2",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP160t1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP192r1
    {
        NID_brainpoolP192r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.3",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP192r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP192t1
    {
        NID_brainpoolP192t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.4",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP192t1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP224r1
    {
        NID_brainpoolP224r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.5",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP224r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP224t1
    {
        NID_brainpoolP224t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.6",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP224t1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP256r1
    {
        NID_brainpoolP256r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x001a,
        "1.3.36.3.3.2.8.1.1.7",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP256r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP256t1
    {
        NID_brainpoolP256t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.8",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP256t1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP320r1
    {
        NID_brainpoolP320r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.9",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP320r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP320t1
    {
        NID_brainpoolP320t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.10",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP320t1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP384r1
    {
        NID_brainpoolP384r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x001b,
        "1.3.36.3.3.2.8.1.1.11",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP384r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP384t1
    {
        NID_brainpoolP384t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.12",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP384t1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP512r1
    {
        NID_brainpoolP512r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x001c,
        "1.3.36.3.3.2.8.1.1.13",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP512r1",
    },
    // https://neuromancer.sk/std/brainpool/brainpoolP512t1
    {
        NID_brainpoolP512t1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        0x0000,
        "1.3.36.3.3.2.8.1.1.14",
        nullptr,
        nullptr,
        nullptr,
        "brainpoolP512t1",
    },
};

const size_t sizeof_hint_curves = RTL_NUMBER_OF(hint_curves);

uint32 nidof(const hint_curve_t* hint) {
    uint32 value = 0;
    if (hint) {
        value = hint->nid;
    }
    return value;
}
cose_ec_curve_t coseof(const hint_curve_t* hint) {
    cose_ec_curve_t value = cose_ec_unknown;
    if (hint) {
        value = hint->cose_crv;
    }
    return value;
}
crypto_kty_t ktyof(const hint_curve_t* hint) {
    crypto_kty_t value = kty_unknown;
    if (hint) {
        value = hint->kty;
    }
    return value;
}
uint16 groupof(const hint_curve_t* hint) {
    uint16 value = 0;
    if (hint) {
        value = hint->group;
    }
    return value;
}
const char* oidof(const hint_curve_t* hint) {
    const char* value = nullptr;
    if (hint) {
        value = hint->oid;
    }
    return value;
}

}  // namespace crypto
}  // namespace hotplace
