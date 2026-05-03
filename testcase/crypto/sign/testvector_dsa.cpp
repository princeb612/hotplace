/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_dsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>
#include <map>

struct test_vector_nist_cavp_dsa_param_t {
    std::string item;
    std::string p;
    std::string q;
    std::string g;
};

struct test_vector_nist_cavp_dsa_t {
    std::string item;
    std::string param;
    std::string alg;
    std::string m;
    std::string x;
    std::string y;
    std::string k;
    std::string r;
    std::string s;
};

void test_yaml_testvector_dsa() {
    _test_case.begin("DSA YAML");

    return_t ret = errorcode_t::success;
    std::map<std::string, test_vector_nist_cavp_dsa_param_t> dsa_params;

    auto lambda_yaml_dsa_param = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_dsa_param_t entry;

            entry.item = item["item"].as<std::string>();
            entry.p = item["p"].as<std::string>();
            entry.q = item["q"].as<std::string>();
            entry.g = item["g"].as<std::string>();

            dsa_params.emplace(entry.item, entry);
        }
    };
    auto lambda_yaml_dsa_testvector = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_dsa_t entry;

            entry.item = item["item"].as<std::string>();
            entry.param = item["param"].as<std::string>();
            entry.alg = item["alg"].as<std::string>();
            entry.m = item["m"].as<std::string>();
            entry.x = item["x"].as<std::string>();
            entry.y = item["y"].as<std::string>();
            entry.k = item["k"].as<std::string>();
            entry.r = item["r"].as<std::string>();
            entry.s = item["s"].as<std::string>();

            auto advisor = crypto_advisor::get_instance();
            auto hint = advisor->hintof_digest(entry.alg);
            auto alg = typeof_alg(hint);

            crypto_key key;
            crypto_keychain keychain;

            binary_t bin_m = base16_decode(entry.m);
            binary_t bin_r = base16_decode(entry.r);
            binary_t bin_s = base16_decode(entry.s);

            auto param = dsa_params[entry.param];
            keychain.add_dsa_b16(&key, nid_dsa, entry.y.c_str(), entry.x.c_str(), param.p.c_str(), param.q.c_str(), param.g.c_str(), keydesc("DSA"));

            auto pkey = key.find("DSA");

            openssl_sign sign;
            ret = sign.verify_dsa(pkey, alg, bin_m, bin_r, bin_s);

            basic_stream bs;
            bs.printf(R"("%s" %s...)", entry.param.c_str(), std::string(entry.m, 8).c_str());

            _test_case.test(ret, __FUNCTION__, "verify signature %s", bs.c_str());

            bin_r.clear();
            bin_s.clear();
            ret = sign.sign_dsa(pkey, alg, bin_m, bin_r, bin_s);
            _logger->hdump("signature r", bin_r);
            _logger->hdump("signature s", bin_s);
            _test_case.test(ret, __FUNCTION__, "sign.gen %s", bs.c_str());
            ret = sign.verify_dsa(pkey, alg, bin_m, bin_r, bin_s);
            _test_case.test(ret, __FUNCTION__, "verify.gen %s", bs.c_str());
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_dsa.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "DSA PARAMETER") {
                lambda_yaml_dsa_param(items);
            } else if (schema == "DSA TESTVECTOR") {
                lambda_yaml_dsa_testvector(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_dsa() { test_yaml_testvector_dsa(); }
