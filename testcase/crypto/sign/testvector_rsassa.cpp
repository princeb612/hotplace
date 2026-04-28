/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_rsassa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

#if 0

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

#endif

struct test_vector_nist_cavp_rsa_key_t {
    std::string item;
    std::string n;
    std::string e;
    std::string d;
};

struct test_vector_nist_cavp_rsa_t {
    std::string item;
    std::string kid;
    std::string alg;
    std::string m;
    std::string s;
    std::string salt;
};

void test_yaml_testvector_rsassa() {
    _test_case.begin("NIST CAVP RSA FIPS186-4 YAML");

    crypto_key key;
    crypto_keychain keychain;
    return_t ret = errorcode_t::success;

    auto lambda_test_rsa_key = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_rsa_key_t entry;

            entry.item = std::move(item["item"].as<std::string>());
            entry.n = std::move(item["n"].as<std::string>());
            entry.e = std::move(item["e"].as<std::string>());
            entry.d = std::move(item["d"].as<std::string>());

            keychain.add_rsa_b16(&key, nid_rsa, entry.n.c_str(), entry.e.c_str(), entry.d.c_str(), keydesc(entry.item));
        };
    };
    auto lambda_test_rsa_testvector = [&](const YAML::Node& items, crypt_sig_type_t scheme) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_rsa_t entry;

            entry.item = std::move(item["item"].as<std::string>());
            entry.kid = std::move(item["kid"].as<std::string>());
            entry.alg = std::move(item["alg"].as<std::string>());
            entry.m = std::move(item["m"].as<std::string>());
            entry.s = std::move(item["s"].as<std::string>());
            if (crypt_sig_rsassa_pss == scheme) {
                auto node_salt = item["salt"];
                // salt:
                //      as<std::string>() return null
                if (false == node_salt.IsNull()) {
                    entry.salt = std::move(node_salt.as<std::string>());
                }
            }

            crypto_sign_builder builder;
            auto s = builder.set_scheme(scheme).set_digest(entry.alg).build();
            if (s) {
                if (crypt_sig_rsassa_pss == scheme) {
                    binary_t salt = std::move(base16_decode(entry.salt));
                    s->set_saltlen(salt.size());
                }

                auto pkey = key.find(entry.kid.c_str());
                if (pkey) {
                    binary_t msg = std::move(base16_decode(entry.m));
                    binary_t sig = std::move(base16_decode(entry.s));

                    if (crypt_sig_rsassa_pkcs15 == scheme) {
                        ret = s->sign(pkey, msg, sig);
                        _logger->hdump("> input", msg);
                        _logger->hdump("> sig", sig);
                        if (base16_decode(entry.s) != sig) {
                            ret = mismatch;
                        }
                        _test_case.test(ret, __FUNCTION__, R"(sign kid:"%s" hash:%s msg:%s...)", entry.kid.c_str(), entry.alg.c_str(), std::string(entry.m, 8).c_str());
                    }

                    ret = s->verify(pkey, msg, sig);
                    _test_case.test(ret, __FUNCTION__, R"(verify kid:"%s" hash:%s msg:%s...)", entry.kid.c_str(), entry.alg.c_str(), std::string(entry.m, 8).c_str());
                } else {
                    ret = not_found;
                    _test_case.test(ret, __FUNCTION__, R"(sign kid:"%s" hash:%s msg:%s...)", entry.kid.c_str(), entry.alg.c_str(), std::string(entry.m, 8).c_str());
                }
                s->release();
            }
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_rsassa.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "RSA KEY") {
                lambda_test_rsa_key(items);
            } else if (schema == "RSA PKCS 1.5") {
                lambda_test_rsa_testvector(items, crypt_sig_rsassa_pkcs15);
            } else if (schema == "RSA PSS") {
                lambda_test_rsa_testvector(items, crypt_sig_rsassa_pss);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_rsassa() { test_yaml_testvector_rsassa(); }
