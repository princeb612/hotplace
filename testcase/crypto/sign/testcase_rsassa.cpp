/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_rsassa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_rsassa_sample() {
    _test_case.begin("RSA key, RSAPSS key");
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    const char* message = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t msglen = strlen(message);

    auto lambda_test = [&](uint32 nid) -> void {
        crypto_key key;
        crypto_keychain keychain;

        keychain.add_rsa(&key, nid, 2048, keydesc("key"));
        auto pkey = key.find("key");

        _logger->write([&](basic_stream& bs) -> void { dump_key(pkey, &bs); });

        auto kty = ktyof_evp_pkey(pkey);
        auto ktyname = advisor->nameof_kty(kty);
        uint32 pkey_nid = 0;
        nidof_evp_pkey(pkey, pkey_nid);
        _test_case.assert(pkey_nid == nid, __FUNCTION__, "check kty %s", ktyname);

        binary_t sig;
        crypto_sign_builder builder;
        auto s = builder.set_scheme(crypt_sig_rsassa_pss).set_digest(sha2_256).build();
        if (s) {
            s->sign(pkey, (byte_t*)message, msglen, sig);
            ret = s->verify(pkey, (byte_t*)message, msglen, sig);
            _logger->dump(sig);
            _test_case.test(ret, __FUNCTION__, "verify kty %s", ktyname);

            s->release();
        }
    };

    lambda_test(NID_rsaEncryption);
    lambda_test(NID_rsassaPss);
}

void testcase_rsassa() { test_rsassa_sample(); }
