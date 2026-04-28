/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_ecdsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void check_ecdsa_size() {
    _test_case.begin("ECDSA signature size");
    crypto_key key;
    crypto_keychain keychain;

#define ADD_KEY(x) keychain.add_ec2(&key, x, keydesc(#x))
    ADD_KEY(NID_secp112r1);
    ADD_KEY(NID_secp112r2);
    ADD_KEY(NID_secp128r1);
    ADD_KEY(NID_secp128r2);
    ADD_KEY(NID_secp160k1);
    ADD_KEY(NID_secp160r1);
    ADD_KEY(NID_secp160r2);
    ADD_KEY(NID_secp192k1);
    ADD_KEY(NID_X9_62_prime192v1);
    ADD_KEY(NID_secp224k1);
    ADD_KEY(NID_secp224r1);
    ADD_KEY(NID_secp256k1);
    ADD_KEY(NID_X9_62_prime256v1);
    ADD_KEY(NID_secp384r1);
    ADD_KEY(NID_secp521r1);
    ADD_KEY(NID_secp521r1);
    ADD_KEY(NID_secp521r1);
    ADD_KEY(NID_sect113r2);
    ADD_KEY(NID_sect131r1);
    ADD_KEY(NID_sect131r2);
    ADD_KEY(NID_sect163k1);
    ADD_KEY(NID_sect163r1);
    ADD_KEY(NID_sect163r2);
    ADD_KEY(NID_sect193r1);
    ADD_KEY(NID_sect193r2);
    ADD_KEY(NID_sect233k1);
    ADD_KEY(NID_sect233r1);
    ADD_KEY(NID_sect239k1);
    ADD_KEY(NID_sect283k1);
    ADD_KEY(NID_sect283r1);
    ADD_KEY(NID_sect409k1);
    ADD_KEY(NID_sect409r1);
    ADD_KEY(NID_sect571k1);
    ADD_KEY(NID_sect571r1);
    ADD_KEY(NID_brainpoolP160r1);
    ADD_KEY(NID_brainpoolP160t1);
    ADD_KEY(NID_brainpoolP192r1);
    ADD_KEY(NID_brainpoolP192t1);
    ADD_KEY(NID_brainpoolP224r1);
    ADD_KEY(NID_brainpoolP224t1);
    ADD_KEY(NID_brainpoolP256r1);
    ADD_KEY(NID_brainpoolP256t1);
    ADD_KEY(NID_brainpoolP320r1);
    ADD_KEY(NID_brainpoolP320t1);
    ADD_KEY(NID_brainpoolP384r1);
    ADD_KEY(NID_brainpoolP384t1);
    ADD_KEY(NID_brainpoolP512r1);
    ADD_KEY(NID_brainpoolP512t1);

    const char* algs[] = {"sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"};
    const char* source = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t len = strlen(source);

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypto_sign_builder builder;
    binary_t sig;

    auto lambda = [&](crypto_key_object* keyobj, void*) -> void {
        for (auto alg : algs) {
            auto pkey = keyobj->get_pkey();

            auto spec = advisor->query_feature(alg);
            if (0 == spec) {
                _test_case.test(not_supported, __FUNCTION__, "not support %s", alg);
                continue;
            }

            uint32 nid = 0;
            nidof_evp_pkey(pkey, nid);
            auto hint = advisor->hintof_curve_nid(nid);
            bool check_support = support(hint, alg);

            crypto_sign* sign = builder.set_scheme(crypt_sig_ecdsa).set_digest(alg).build();
            if (sign) {
                ret = sign->sign(pkey, (byte_t*)source, len, sig);
                auto kid = keyobj->get_desc().get_kid_cstr();
                basic_stream desc;
                desc.printf("%-7s using %-20s", alg, kid);

                if (success == ret) {
                    desc.printf(" signature size %-3zi", sig.size());
                    _logger->hdump(desc.c_str(), sig);
                } else {
                    if (false == check_support) {
                        desc.printf(" not supported (cross-check hint_curve_t::flags)");
                        ret = errorcode_t::expect_failure;  // expected
                    }
                }

                _test_case.test(ret, __FUNCTION__, "%s", desc.c_str());
                sign->release();
            }
        }
    };
    key.for_each(lambda, nullptr);
}

void testcase_ecdsa() { check_ecdsa_size(); }
