/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <iostream>

namespace hotplace {
namespace crypto {

/*
 * Standard curve database - NIST, ANSI X9.62 & X9.63, SECG, ...
 * https://neuromancer.sk/std/
 */
const hint_curve_t hint_curves[] = {
    {
        NID_X9_62_prime256v1,
        cose_ec_curve_t::cose_ec_p256,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-256",
        "prime256v1",
        "secp256r1",
    },
    {
        NID_secp384r1,
        cose_ec_curve_t::cose_ec_p384,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-384",
        "ansip384r1",
        "secp384r1",
    },
    {
        NID_secp521r1,
        cose_ec_curve_t::cose_ec_p521,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-521",
        "ansip521r1",
        "secp521r1",
    },
    {
        NID_ED25519,
        cose_ec_curve_t::cose_ec_ed25519,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_sig,
        "Ed25519",
    },
    {
        NID_ED448,
        cose_ec_curve_t::cose_ec_ed448,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_sig,
        "Ed448",
    },
    {
        NID_X25519,
        cose_ec_curve_t::cose_ec_x25519,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_enc,
        "X25519",
    },
    {
        NID_X448,
        cose_ec_curve_t::cose_ec_x448,
        crypto_kty_t::kty_okp,
        crypto_use_t::use_enc,
        "X448",
    },
    {
        NID_secp224r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-224",
        "ansip224r1",
        "secp224r1",
        "wap-wsg-idm-ecid-wtls12",
    },

    // openssl-3.0
    {
        NID_X9_62_prime192v1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "P-192",
        "prime192v1",
        "secp192r1",
    },
    {
        NID_sect163k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-163",
        nullptr,
        "sect163k1",
    },
    {
        NID_sect233k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-233",
        "ansit233k1",
        "sect233k1",
        "wap-wsg-idm-ecid-wtls10",
    },
    {
        NID_sect283k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-283",
        "ansit283k1",
        "sect283k1",
    },
    {
        NID_sect409k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-409",
        "ansit409k1",
        "sect409k1",
    },
    {
        NID_sect571k1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "K-571",
        "ansit571k1",
        "sect571k1",
    },
    {
        NID_sect163r2,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-163",
        "ansit163r2",
        "sect163r2",
    },
    {
        NID_sect233r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-233",
        "ansit233r1",
        "sect233r1",
        "wap-wsg-idm-ecid-wtls11",
    },
    {
        NID_sect283r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-283",
        "ansit283r1",
        "sect283r1",
    },
    {
        NID_sect409r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-409",
        "ansit409r1",
        "sect409r1",
    },
    {
        NID_sect571r1,
        cose_ec_curve_t::cose_ec_unknown,
        crypto_kty_t::kty_ec,
        crypto_use_t::use_any,
        "B-571",
        "ansit571r1",
        "sect571r1",
    },
};

const size_t sizeof_hint_curves = RTL_NUMBER_OF(hint_curves);

}  // namespace crypto
}  // namespace hotplace
