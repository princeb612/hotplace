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

void test_mldsa() {
    _test_case.begin("ML-DSA");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    crypto_key key;
    crypto_keychain keychain;
    keychain.add_mldsa(&key, NID_ML_DSA_44, keydesc("NID_ML_DSA_44"));
    keychain.add_mldsa(&key, NID_ML_DSA_65, keydesc("NID_ML_DSA_65"));
    keychain.add_mldsa(&key, NID_ML_DSA_87, keydesc("NID_ML_DSA_87"));
    const char* sample = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";

    auto lambda = [&](const char* kid) -> void {
        return_t ret = errorcode_t::success;
        openssl_sign sign;
        binary_t sig;
        auto pkey_mldsa = key.find(kid);
        ret = sign.sign_mldsa(pkey_mldsa, (byte_t*)sample, strlen(sample), sig);
        _logger->hdump("signature", sig, 16, 3);
        _test_case.test(ret, __FUNCTION__, "sign %s size %zi", kid, sig.size());
        ret = sign.verify_mldsa(pkey_mldsa, (byte_t*)sample, strlen(sample), sig);
        _test_case.test(ret, __FUNCTION__, "verify %s", kid);
    };

    lambda("NID_ML_DSA_44");
    lambda("NID_ML_DSA_65");
    lambda("NID_ML_DSA_87");
#else
    _test_case.test(not_supported, __FUNCTION__, "not supported");
#endif
}

void testcase_mldsa() { test_mldsa(); }
