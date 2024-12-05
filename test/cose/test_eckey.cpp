/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_eckey_compressed() {
    _test_case.begin("EC compressed");
    basic_stream bs;
    crypto_keychain keychain;
    crypto_key key;
    binary_t bin_x;
    binary_t bin_y;
    binary_t bin_d;

    keychain.add_ec_b16(&key, ec_p256, "98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280", true, nullptr, keydesc("test"));
    key.for_each(dump_crypto_key, nullptr);

    const EVP_PKEY* pkey = key.any();
    key.get_key(pkey, bin_x, bin_y, bin_d, true);
    // Appendix_C_3_1
    // x mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA
    // y 8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs
    std::string y_compressed("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs");
    bool test = (bin_y == base64_decode(y_compressed, base64_encoding_t::base64url_encoding));
    _test_case.assert(test, __FUNCTION__, "EC compressed");
}
