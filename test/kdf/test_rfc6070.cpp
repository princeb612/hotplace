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

void test_kdf_pbkdf2_rfc6070() {
    _test_case.begin("pbkdf2");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    openssl_kdf kdf;

    // RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
    // 2.  PBKDF2 HMAC-SHA1 Test Vectors
    struct {
        const char* password;
        size_t size_password;
        const char* salt;
        size_t size_salt;
        int c;
        int dlen;
        const char* expect;
    } vector[] = {
        {"password", 8, "salt", 4, 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
        {"password", 8, "salt", 4, 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
        {"password", 8, "salt", 4, 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
        {"password", 8, "salt", 4, 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"},
        {"passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
        {"pass\0word", 9, "sa\0lt", 5, 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"},
    };

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        binary_t password;
        password.insert(password.end(), vector[i].password, vector[i].password + vector[i].size_password);
        binary_t salt;
        salt.insert(salt.end(), vector[i].salt, vector[i].salt + vector[i].size_salt);
        kdf.pbkdf2(result, hash_algorithm_t::sha1, vector[i].dlen, password, salt, vector[i].c);

        if (option.verbose) {
            _logger->dump(result);
        }

        _test_case.assert(base16_decode(vector[i].expect) == result, __FUNCTION__, "RFC6070.pbkdf2 c = %i", vector[i].c);
    }
}
