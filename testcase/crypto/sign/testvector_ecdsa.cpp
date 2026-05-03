/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_ecdsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

struct test_vector_nist_cavp_ecdsa_t {
    std::string encoding;
    std::string item;
    std::string curve;
    std::string alg;
    std::string m;
    std::string d;
    std::string x;
    std::string y;
    std::string k;
    std::string r;
    std::string s;
};

void do_test_ecdsa(const test_vector_nist_cavp_ecdsa_t* entry) {
    __try2 {
        if (nullptr == entry) {
            __leave2;
        }

        auto advisor = crypto_advisor::get_instance();
        auto spec_crv = advisor->query_feature(entry->curve);
        if (0 == spec_crv) {
            _test_case.test(not_supported, __FUNCTION__, "skip %s", entry->curve.c_str());
            __leave2;
        }
        auto spec_alg = advisor->query_feature(entry->alg);
        if (0 == spec_alg) {
            _test_case.test(not_supported, __FUNCTION__, "skip %s", entry->alg.c_str());
            __leave2;
        }

        binary_t message;
        if (entry->encoding == "base16") {
            message = base16_decode(entry->m);
        } else if (entry->encoding == "plain") {
            message = str2bin(entry->m);
        } else {
            _test_case.assert(false, __FUNCTION__, "bad message format");
            __leave2;
        }

        crypto_key key;
        crypto_keychain keychain;
        keychain.add_ec_b16(&key, entry->curve.c_str(), entry->x.c_str(), entry->y.c_str(), entry->d.c_str(), keydesc());
        auto pkey = key.any();

        // R || S
        binary_t signature;
        binary_t bin_r = base16_decode(entry->r);
        binary_t bin_s = base16_decode(entry->s);
        signature.insert(signature.end(), bin_r.begin(), bin_r.end());
        signature.insert(signature.end(), bin_s.begin(), bin_s.end());

        _logger->writeln("curve %s", entry->curve.c_str());
        _logger->writeln("al    %s", entry->alg.c_str());
        _logger->writeln("m     %s", entry->m.c_str());
        _logger->writeln("d     %s", entry->d.c_str());
        _logger->writeln("x     %s", entry->x.c_str());
        _logger->writeln("y     %s", entry->y.c_str());
        _logger->writeln("k     %s", entry->k.c_str());
        _logger->writeln("r     %s", entry->r.c_str());
        _logger->writeln("s     %s", entry->s.c_str());

        return_t ret = errorcode_t::success;
        {
            openssl_sign sign;

            auto hint = advisor->hintof_digest(entry->alg);

            ret = sign.verify_ecdsa(pkey, typeof_alg(hint), message, signature);
            _test_case.test(ret, __FUNCTION__, "verify %s %s", entry->curve.c_str(), entry->alg.c_str());
        }

        {
            auto hint = advisor->hintof_curve(entry->curve);

            crypto_sign_builder builder;
            crypto_sign* sign = builder.set_scheme(crypt_sig_ecdsa).set_digest(entry->alg).build();
            if (sign) {
                ret = sign->verify(pkey, message, signature);
                _test_case.test(ret, __FUNCTION__, "ECDSA.crypto_sign  %s %s", hint ? hint->name_nist : "", entry->alg.c_str());
                sign->release();
            }
        }
    }
    __finally2 {}
}

void test_yaml_testvector_ecdsa() {
    _test_case.begin("ECDSA YAML");

    auto lambda_yaml_ecdsa_testvector = [&](const YAML::Node& items, const std::string& encoding) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_ecdsa_t entry;

            entry.encoding = encoding;
            entry.item = item["item"].as<std::string>();
            entry.curve = item["curve"].as<std::string>();
            entry.alg = item["alg"].as<std::string>();
            entry.m = item["m"].as<std::string>();
            entry.d = item["d"].as<std::string>();
            entry.x = item["x"].as<std::string>();
            entry.y = item["y"].as<std::string>();
            entry.k = item["k"].as<std::string>();
            entry.r = item["r"].as<std::string>();
            entry.s = item["s"].as<std::string>();

            do_test_ecdsa(&entry);
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_ecdsa.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "ECDSA TESTVECTOR") {
                auto encoding = example["encoding"].as<std::string>();

                lambda_yaml_ecdsa_testvector(items, encoding);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_ecdsa() { test_yaml_testvector_ecdsa(); }
