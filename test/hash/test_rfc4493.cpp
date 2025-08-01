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

void do_test_aes128cbc_mac_routine(const binary_t& key, const binary_t& message, const binary_t& expect) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    openssl_hash hash;
    hash_context_t* handle = nullptr;
    binary_t result;

    ret = hash.open(&handle, crypt_algorithm_t::aes128, crypt_mode_t::cbc, key.empty() ? nullptr : &key[0], key.size());
    if (errorcode_t::success == ret) {
        // Figure 2.3.  Algorithm AES-CMAC
        hash.init(handle);
        hash.update(handle, message.empty() ? nullptr : &message[0], message.size());
        hash.finalize(handle, result);
        hash.close(handle);

        if (option.verbose) {
            _logger->hdump("result", result);
        }
    }
    // Figure 2.4.  Algorithm Verify_MAC
    _test_case.assert(expect == result, __FUNCTION__, "cmac test");
}

void test_cmac_rfc4493() {
    _test_case.begin("CMAC (RFC 4493)");

    openssl_hash hash;

    constexpr char constexpr_key[] = "2b7e151628aed2a6abf7158809cf4f3c";

    struct test_vector {
        const char* message;
        const char* result;
    } tests[] = {
        {
            "",
            "bb1d6929e95937287fa37d129b756746",
        },
        {
            "6bc1bee22e409f96e93d7e117393172a",
            "070a16b46b4d4144f79bdd9dd04a287c",
        },
        {
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
            "dfa66747de9ae63030ca32611497c827",
        },
        {
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
            "51f0bebf7e3b9d92fc49741779363cfe",
        },
    };

    binary_t bin_k1 = std::move(base16_decode(constexpr_key));

    for (int i = 0; i < RTL_NUMBER_OF(tests); i++) {
        do_test_aes128cbc_mac_routine(bin_k1, base16_decode(tests[i].message), base16_decode(tests[i].result));
    }
}
