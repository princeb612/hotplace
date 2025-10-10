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

void dotest_nist_cavp_rsa_signgen15(crypto_key* key, const test_vector_nist_cavp_rsa_t* tv, size_t tvsize) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypto_sign_builder builder;
    for (auto i = 0; i < tvsize; i++) {
        return_t ret = success;
        auto item = tv + i;
        auto s = builder.set_scheme(crypt_sig_rsassa_pkcs15).set_digest(item->alg).build();
        const char* hashalg = advisor->nameof_md(item->alg);
        if (s) {
            auto pkey = key->find(item->kid);
            if (pkey) {
                binary_t msg = std::move(base16_decode(item->msg));
                binary_t signature;
                ret = s->sign(pkey, msg, signature);
                _logger->hdump("> input", msg);
                _logger->hdump("> signature", signature);
                if (base16_decode(item->s) != signature) {
                    ret = mismatch;
                }
                _test_case.test(ret, __FUNCTION__, R"(sign kid:"%s" hash:%s msg:%s...)", item->kid, hashalg, std::string(item->msg, 8).c_str());

                ret = s->verify(pkey, msg, signature);
                _test_case.test(ret, __FUNCTION__, R"(verify kid:"%s" hash:%s msg:%s...)", item->kid, hashalg, std::string(item->msg, 8).c_str());
            } else {
                ret = not_found;
            }
            s->release();
        } else {
            ret = not_supported;
        }
    }
}

void dotest_nist_cavp_rsa_signpss(crypto_key* key, const test_vector_nist_cavp_rsa_t* tv, size_t tvsize) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypto_sign_builder builder;
    for (auto i = 0; i < tvsize; i++) {
        return_t ret = success;
        auto item = tv + i;
        auto s = builder.set_scheme(crypt_sig_rsassa_pss).set_digest(item->alg).build();
        const char* hashalg = advisor->nameof_md(item->alg);
        if (s) {
            if (item->salt) {
                binary_t salt = std::move(base16_decode(item->salt));
                s->set_saltlen(salt.size());  // set saltlen
            }
            auto pkey = key->find(item->kid);
            if (pkey) {
                binary_t msg = std::move(base16_decode(item->msg));
                binary_t signature = std::move(base16_decode(item->s));
                ret = s->verify(pkey, msg, signature);
                _logger->hdump("> input", msg);
                _logger->hdump("> signature", signature);
            } else {
                ret = not_found;
            }
            s->release();
        } else {
            ret = not_supported;
        }
        _test_case.test(ret, __FUNCTION__, R"(verify kid:"%s" hash:%s msg:%s...)", item->kid, hashalg, std::string(item->msg, 8).c_str());
    }
}

void test_nist_cavp_rsa() {
    _test_case.begin("NIST CAVP RSA FIPS186-4");

    crypto_key key_rsa;
    crypto_keychain keychain;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    for (auto i = 0; i < sizeof_test_vector_nist_cavp_rsa_fips186_4_keys; i++) {
        auto item = test_vector_nist_cavp_rsa_fips186_4_keys + i;
        keychain.add_rsa_b16(&key_rsa, nid_rsa, item->n, item->e, item->d, keydesc(item->kid));
    }
    dotest_nist_cavp_rsa_signgen15(&key_rsa, test_vector_nist_cavp_rsa_fips186_4_signgen15_186_3, sizeof_test_vector_nist_cavp_rsa_fips186_4_signgen15_186_3);
    // do not test FIPS186-3 and X9.31
    dotest_nist_cavp_rsa_signpss(&key_rsa, test_vector_nist_cavp_rsa_fips186_4_signgenpss_186_3, sizeof_test_vector_nist_cavp_rsa_fips186_4_signgenpss_186_3);
}

void test_rsassa() {
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
