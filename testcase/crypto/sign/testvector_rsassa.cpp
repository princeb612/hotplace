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

    auto lambda_yaml_rsa_key = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_rsa_key_t entry;

            entry.item = item["item"].as<std::string>("");
            entry.n = item["n"].as<std::string>("");
            entry.e = item["e"].as<std::string>("");
            entry.d = item["d"].as<std::string>("");

            keychain.add_rsa_b16(&key, nid_rsa, entry.n.c_str(), entry.e.c_str(), entry.d.c_str(), keydesc(entry.item));
        };
    };
    auto lambda_yaml_rsa = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        sig_category_t category = {};
        auto schema = example["schema"].as<std::string>("");
        if (schema == "RSA PKCS 1.5")
            category = sig_category_t::rsassa_pkcs15;
        else if (schema == "RSA PSS")
            category = sig_category_t::rsassa_pss;

        for (const auto& item : items) {
            test_vector_nist_cavp_rsa_t entry;

            entry.item = item["item"].as<std::string>("");
            entry.kid = item["kid"].as<std::string>("");
            entry.alg = item["alg"].as<std::string>("");
            entry.m = item["m"].as<std::string>("");
            entry.s = item["s"].as<std::string>("");
            if (sig_category_t::rsassa_pss == category) {
                auto node_salt = item["salt"];
                // salt:
                //      as<std::string>("") return null
                if (false == node_salt.IsNull()) {
                    entry.salt = node_salt.as<std::string>("");
                }
            }

            crypto_sign_builder builder;
            auto s = builder.set_category(category).set_digest(entry.alg).build();
            if (s) {
                if (sig_category_t::rsassa_pss == category) {
                    binary_t salt = base16_decode(entry.salt);
                    s->set_saltlen(t_narrow_cast(salt.size()));
                }

                auto pkey = key.find(entry.kid.c_str());
                if (pkey) {
                    binary_t msg = base16_decode(entry.m);
                    binary_t sig = base16_decode(entry.s);

                    if (sig_category_t::rsassa_pkcs15 == category) {
                        ret = s->sign(pkey, msg, sig);
                        _logger->hdump("> input", msg);
                        _logger->hdump("> sig", sig);
                        if (base16_decode(entry.s) != sig) {
                            ret = errorcode_t::mismatch;
                        }
                        _test_case.test(ret, __FUNCTION__, R"(sign kid:"%s" hash:%s msg:%s...)", entry.kid.c_str(), entry.alg.c_str(), std::string(entry.m, 8).c_str());
                    }

                    ret = s->verify(pkey, msg, sig);
                    _test_case.test(ret, __FUNCTION__, R"(verify kid:"%s" hash:%s msg:%s...)", entry.kid.c_str(), entry.alg.c_str(), std::string(entry.m, 8).c_str());
                } else {
                    ret = errorcode_t::not_found;
                    _test_case.test(ret, __FUNCTION__, R"(sign kid:"%s" hash:%s msg:%s...)", entry.kid.c_str(), entry.alg.c_str(), std::string(entry.m, 8).c_str());
                }
                s->release();
            }
        }
    };

    yaml_testcase test;
    test.add("RSA KEY", lambda_yaml_rsa_key).add("RSA PKCS 1.5", lambda_yaml_rsa).add("RSA PSS", lambda_yaml_rsa).run("testvector_rsassa.yml");
}

void testcase_testvector_rsassa() { test_yaml_testvector_rsassa(); }
