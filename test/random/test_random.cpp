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

void test_random() {
    _test_case.begin("random");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    uint32 value = 0;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        value = random.rand32();
        if (option.verbose) {
            _logger->writeln("rand %08x", (int)value);
        }
    }

    _test_case.test(ret, __FUNCTION__, "random loop %i times", times);
}

void test_nonce() {
    _test_case.begin("random");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    std::string nonce;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        nonce = random.nonce(16, encoding_t::encoding_base16);
        if (option.verbose) {
            _logger->writeln("nonce.1 %s", nonce.c_str());
        }
    }
    for (i = 0; i < times; i++) {
        nonce = random.rand(16, encoding_t::encoding_base16, true);
        if (option.verbose) {
            _logger->writeln("nonce.2 %s", nonce.c_str());
        }
    }

    _test_case.test(ret, __FUNCTION__, "nonce loop %i times", times);
}

void test_token() {
    _test_case.begin("random");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    std::string token;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        token = random.token(16, encoding_t::encoding_base64url);
        if (option.verbose) {
            _logger->writeln("token.1 %s", token.c_str());
        }
    }
    for (i = 0; i < times; i++) {
        token = random.rand(16, encoding_t::encoding_base64url, true);
        if (option.verbose) {
            _logger->writeln("token.2 %s", token.c_str());
        }
    }

    _test_case.test(ret, __FUNCTION__, "token loop %i times", times);
}
