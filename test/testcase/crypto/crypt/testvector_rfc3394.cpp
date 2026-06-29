/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_rfc3394.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/crypto/sample.hpp>

typedef struct _test_vector_rfc3394_t {
    std::string item;
    std::string alg;
    std::string kek;
    std::string key;
    std::string keydata;
} test_vector_rfc3394_t;

void do_test_keywrap_rfc3394_testvector(const test_vector_rfc3394_t* entry) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    _test_case.reset_time();

    std::string alg = entry->alg;
    binary_t kek = base16_decode(entry->kek);
    binary_t key = base16_decode(entry->key);
    binary_t keydata = base16_decode(entry->keydata);
    const char* msg = entry->item.c_str();

    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    binary_t iv;
    binary_fill(iv, 8, 0xa6);
    binary_t out_kw, out_kuw;

    ret = crypt.open(&handle, alg, kek, iv);
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, key.data(), key.size(), out_kw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->writeln("alg %s", alg.c_str());

            _logger->hdump("kek", kek);
            _logger->hdump("key", key);
            _logger->hdump("keywrap", out_kw);
        }

        crypt.decrypt(handle, out_kw.data(), out_kw.size(), out_kuw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("key", out_kuw);
        }

        crypt.close(handle);
    }
    _test_case.assert(out_kw == keydata, __FUNCTION__, msg ? msg : "");

    ret = crypt.open(&handle, alg, kek, iv);
    if (errorcode_t::success == ret) {
        crypt.encrypt(handle, key.data(), key.size(), out_kw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->writeln("alg %s", alg.c_str());

            _logger->hdump("kek", kek);
            _logger->hdump("key", key);
            _logger->hdump("keywrap", out_kw);
        }

        crypt.decrypt(handle, out_kw.data(), out_kw.size(), out_kuw);

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("key", out_kuw);
        }

        crypt.close(handle);
    }
    _test_case.assert(out_kw == keydata, __FUNCTION__, msg ? msg : "");
}

void test_yaml_testvector_rfc3394() {
    _test_case.begin("RFC 3394 keywrap YAML");

    auto lambda_yaml_rfc3394 = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_rfc3394_t entry;

            entry.item = item["item"].as<std::string>("");
            entry.alg = item["alg"].as<std::string>("");
            entry.kek = item["kek"].as<std::string>("");
            entry.key = item["key"].as<std::string>("");
            entry.keydata = item["keydata"].as<std::string>("");

            do_test_keywrap_rfc3394_testvector(&entry);
        }
    };

    yaml_testcase test;
    test.add("RFC 3394", lambda_yaml_rfc3394).run("testvector_rfc3394.yml");
}

void testcase_testvector_rfc3394() { test_yaml_testvector_rfc3394(); }
