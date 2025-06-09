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

typedef struct _TOTP_TEST_DATA {
    hash_algorithm_t algorithm;
    byte_t* key;
    size_t key_size;
    uint32 result[6];
} TOTP_TEST_DATA;
TOTP_TEST_DATA _totp_test_data[] = {
    {
        hash_algorithm_t::sha1,
        (byte_t*)"12345678901234567890",
        20,
        {
            94287082,
            7081804,
            14050471,
            89005924,
            69279037,
            65353130,
        },
    }, /* sha1 */
    {
        hash_algorithm_t::sha2_256,
        (byte_t*)"12345678901234567890123456789012",
        32,
        {
            46119246,
            68084774,
            67062674,
            91819424,
            90698825,
            77737706,
        },
    }, /* sha256 */
    {
        hash_algorithm_t::sha2_512,
        (byte_t*)"1234567890123456789012345678901234567890123456789012345678901234",
        64,
        {
            90693936,
            25091201,
            99943326,
            93441116,
            38618901,
            47863826,
        },
    }, /* sha512 */
};

uint32 test_totp_rfc6238(hash_algorithm_t algorithm) {
    _test_case.begin("TOTP/SHA1 (RFC6238)");
    const OPTION& option = _cmdline->value();

    uint32 ret = errorcode_t::success;
    otp_context_t* handle = nullptr;
    TOTP_TEST_DATA* test_data = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        for (size_t index = 0; index < RTL_NUMBER_OF(_totp_test_data); index++) {
            if (algorithm == _totp_test_data[index].algorithm) {
                test_data = _totp_test_data + index;
                break;
            }
        }
        if (nullptr == test_data) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        time_otp totp;
        std::vector<uint32> output;
        ret = totp.open(&handle, 8, 30, algorithm, test_data->key, test_data->key_size);
        if (errorcode_t::success == ret) {
            uint32 code = 0;
            uint64 counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000LL, 20000000000LL};
            for (int i = 0; i < (int)RTL_NUMBER_OF(counter); i++) {
                totp.get(handle, counter[i], code);
                output.push_back(code);

                if (option.verbose) {
                    test_case_notimecheck notimecheck(_test_case);
                    _logger->writeln("counter %I64u code %u", counter[i], code);
                }
            }
            totp.close(handle);
        }

        if (0 != memcmp(&output[0], test_data->result, 6 * sizeof(uint32))) {
            ret = errorcode_t::internal_error;
        }
    }
    __finally2 {
        const char* alg = advisor->nameof_md(algorithm);
        _test_case.test(ret, __FUNCTION__, "RFC6238 TOTP algorithm %s + 6 test vectors tested", alg ? alg : "");
    }

    return ret;
}
