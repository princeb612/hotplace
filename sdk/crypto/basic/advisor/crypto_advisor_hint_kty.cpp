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

const hint_kty_name_t hint_kty_names[] = {
    {
        crypto_kty_t::kty_oct,
        "oct",
    },
    {
        crypto_kty_t::kty_rsa,
        "RSA",
    },
    {
        crypto_kty_t::kty_rsapss,
        "RSAPSS",
    },
    {
        crypto_kty_t::kty_ec,
        "EC",
    },
    {
        crypto_kty_t::kty_okp,
        "OKP",
    },
    {
        crypto_kty_t::kty_dh,
        "DH",
    },
    {
        crypto_kty_t::kty_dsa,
        "DSA",
    },
};

const size_t sizeof_hint_kty_names = RTL_NUMBER_OF(hint_kty_names);

}  // namespace crypto
}  // namespace hotplace
