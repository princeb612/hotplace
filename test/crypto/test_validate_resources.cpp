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

void test_validate_resources() {
    // after modification, check sanities
    _test_case.begin("validate resources");

    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto lambda = [&](const hint_cipher_t* hint) -> void {
        auto test = ((hint->scheme) & 0x0000ffff) == (CRYPTO_SCHEME16(hint->algorithm, hint->mode));
        _test_case.assert(test, __FUNCTION__, "%s test scheme and {algorithm, mode}", hint->fetchname);

        auto hint_crosscheck = advisor->hintof_cipher(hint->fetchname);
        auto test_crosscheck = ((hint->scheme) & 0x0000ffff) == (CRYPTO_SCHEME16(hint_crosscheck->algorithm, hint_crosscheck->mode));
        _test_case.assert(test_crosscheck, __FUNCTION__, "%s test fetchname and {algorithm, mode}", hint->fetchname);
    };
    advisor->for_each_cipher(lambda);
}
