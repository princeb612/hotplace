/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_akp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/

void test_akp() {
    _test_case.begin("AKP");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    crypto_key key;
    crypto_keychain keychain;
    return_t ret = errorcode_t::success;

    keychain.add_ossl3(&key, "ML-DSA-44", keydesc("ML-DSA-44"));
    keychain.add_ossl3(&key, "ML-DSA-65", keydesc("ML-DSA-65"));
    keychain.add_ossl3(&key, "ML-DSA-87", keydesc("ML-DSA-87"));

    json_web_signature jws;
    const char* payload = "It's a dangerous business, Frodo, going out your door.";
    std::string signature;
    auto lambda_test = [&](jws_t sig) -> void {
        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_jose_signature(sig);
        bool result = false;

        _logger->writeln("alg %s", hint->jws_name);
        _logger->writeln("payload %s", payload);

        ret = jws.sign(&key, sig, payload, signature);

        _logger->writeln("signature");
        _logger->writeln(signature);
        _test_case.test(ret, __FUNCTION__, "sign");

        ret = jws.verify(&key, signature, result);
        _test_case.test(ret, __FUNCTION__, "verify");
    };

    lambda_test(jws_mldsa44);
    lambda_test(jws_mldsa65);
    lambda_test(jws_mldsa87);
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_akp() { test_akp(); }
