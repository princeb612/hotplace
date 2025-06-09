/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_kdf_argon_rfc9106() {
    _test_case.begin("argon2d,argon2i,argon2id");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    // openssl-3.2
    struct {
        argon2_t mode;
        const char* password;
        const char* salt;
        const char* secret;
        const char* ad;
        const char* expect;
        const char* message;
    } vector[] = {
        {
            // 5.1.  Argon2d Test Vectors
            argon2_t::argon2d,
            "0101010101010101010101010101010101010101010101010101010101010101",
            "02020202020202020202020202020202",
            "0303030303030303",
            "040404040404040404040404",
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            "RFC 9106 5.1.  Argon2d Test Vectors",
        },
        {
            // 5.2.  Argon2i Test Vectors
            argon2_t::argon2i,
            "0101010101010101010101010101010101010101010101010101010101010101",
            "02020202020202020202020202020202",
            "0303030303030303",
            "040404040404040404040404",
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            "RFC 9106 5.2.  Argon2i Test Vectors",
        },
        {
            // 5.3.  Argon2id Test Vectors
            argon2_t::argon2id,
            "0101010101010101010101010101010101010101010101010101010101010101",
            "02020202020202020202020202020202",
            "0303030303030303",
            "040404040404040404040404",
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            "RFC 9106 5.3.  Argon2id Test Vectors",
        },
    };

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        binary_t derived;

        auto test = kdf.argon2(derived, vector[i].mode, 32, base16_decode(vector[i].password), base16_decode(vector[i].salt), base16_decode(vector[i].ad),
                               base16_decode(vector[i].secret));

        if (errorcode_t::success == test) {
            _logger->dump(derived);
            _test_case.assert(derived == base16_decode(vector[i].expect), __FUNCTION__, "argon2id");
        } else {
            _test_case.test(test, __FUNCTION__, "argon2d,argon2i,argon2id at least openssl 3.2 required");
        }
    }
}
