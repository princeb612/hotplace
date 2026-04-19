/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

return_t test_rfc4226() {
    _test_case.begin("HOTP (RFC 4226)");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    otp_context_t* handle = nullptr;

    hmac_otp hotp;
    std::vector<uint32> output;
    byte_t* key = (byte_t*)"12345678901234567890";  // 20
    ret = hotp.open(&handle, 6, hash_algorithm_t::sha1, key, 20);
    if (errorcode_t::success == ret) {
        uint32 code = 0;
        for (int i = 0; i < 10; i++) {
            hotp.get(handle, code);
            output.push_back(code);

            if (option.verbose) {
                test_case_notimecheck notimecheck(_test_case);
                _logger->writeln("counter %i code %u", i, code);
            }
        }

        hotp.close(handle);
    }

    uint32 sha1_hotp_result[10] = {
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    };
    auto results = RTL_NUMBER_OF(sha1_hotp_result);
    if ((results != output.size()) || (0 != memcmp(output.data(), &sha1_hotp_result[0], results * sizeof(uint32)))) {
        ret = errorcode_t::mismatch;
    }

    _test_case.test(ret, __FUNCTION__, "RFC4226 HOTP algoritm sha1 + 10 test vectors tested");

    return ret;
}

void testcase_rfc4226() { test_rfc4226(); }
