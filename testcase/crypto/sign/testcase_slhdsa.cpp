/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_slhdsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_slhdsa() {
    _test_case.begin("SLH-DSA");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    crypto_key key;
    crypto_keychain keychain;
    keychain.add_ossl3(&key, "SLH-DSA-SHA2-128s", keydesc("SLH-DSA-SHA2-128s"));
    keychain.add_ossl3(&key, "SLH-DSA-SHA2-128f", keydesc("SLH-DSA-SHA2-128f"));
    keychain.add_ossl3(&key, "SLH-DSA-SHA2-192s", keydesc("SLH-DSA-SHA2-192s"));
    keychain.add_ossl3(&key, "SLH-DSA-SHA2-192f", keydesc("SLH-DSA-SHA2-192f"));
    keychain.add_ossl3(&key, "SLH-DSA-SHA2-256s", keydesc("SLH-DSA-SHA2-256s"));
    keychain.add_ossl3(&key, "SLH-DSA-SHA2-256f", keydesc("SLH-DSA-SHA2-256f"));
    keychain.add_ossl3(&key, "SLH-DSA-SHAKE-128s", keydesc("SLH-DSA-SHAKE-128s"));
    keychain.add_ossl3(&key, "SLH-DSA-SHAKE-128f", keydesc("SLH-DSA-SHAKE-128f"));
    keychain.add_ossl3(&key, "SLH-DSA-SHAKE-192s", keydesc("SLH-DSA-SHAKE-192s"));
    keychain.add_ossl3(&key, "SLH-DSA-SHAKE-192f", keydesc("SLH-DSA-SHAKE-192f"));
    keychain.add_ossl3(&key, "SLH-DSA-SHAKE-256s", keydesc("SLH-DSA-SHAKE-256s"));
    keychain.add_ossl3(&key, "SLH-DSA-SHAKE-256f", keydesc("SLH-DSA-SHAKE-256f"));

    const char* sample = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";

    auto lambda = [&](const char* kid) -> void {
        return_t ret = errorcode_t::success;
        openssl_sign sign;
        binary_t sig;
        auto pkey_mldsa = key.find(kid);
        ret = sign.sign_slhdsa(pkey_mldsa, (byte_t*)sample, strlen(sample), sig);
        _logger->writeln([&](basic_stream& bs) -> void {
            bs.println("signature");
            bs << base16_encode(sig);
        });
        _test_case.test(ret, __FUNCTION__, "sign %s size %zi", kid, sig.size());
        ret = sign.verify_slhdsa(pkey_mldsa, (byte_t*)sample, strlen(sample), sig);
        _test_case.test(ret, __FUNCTION__, "verify %s", kid);
    };

    lambda("SLH-DSA-SHA2-128s");
    lambda("SLH-DSA-SHA2-128f");
    lambda("SLH-DSA-SHA2-192s");
    lambda("SLH-DSA-SHA2-192f");
    lambda("SLH-DSA-SHA2-256s");
    lambda("SLH-DSA-SHA2-256f");
    lambda("SLH-DSA-SHAKE-128s");
    lambda("SLH-DSA-SHAKE-128f");
    lambda("SLH-DSA-SHAKE-192s");
    lambda("SLH-DSA-SHAKE-192f");
    lambda("SLH-DSA-SHAKE-256s");
    lambda("SLH-DSA-SHAKE-256f");
#else
    _test_case.test(not_supported, __FUNCTION__, "not supported");
#endif
}

void testcase_slhdsa() { test_slhdsa(); }
