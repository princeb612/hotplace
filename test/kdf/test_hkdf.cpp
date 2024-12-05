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

void test_kdf_hkdf() {
    _test_case.begin("hkdf");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;

    return_t ret = errorcode_t::success;

    struct {
        const char* password;
        const char* salt;
        const char* info;
        int dlen;
        const char* expect;
    } vector[] = {
        {"secret", "salt", "label", 10, "2ac4369f525996f8de13"},
    };

    binary_t result;

    for (int i = 0; i < RTL_NUMBER_OF(vector); i++) {
        kdf.hmac_kdf(result, hash_algorithm_t::sha2_256, vector[i].dlen, str2bin(vector[i].password), str2bin(vector[i].salt), str2bin(vector[i].info));

        if (option.verbose) {
            _logger->dump(result);
        }

        _test_case.assert(base16_decode(vector[i].expect) == result, __FUNCTION__, "hkdf");
    }
}
