/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_rfc7539.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/crypto/sample.hpp>

typedef struct _test_vector_rfc7539_t {
    std::string item;
    std::string alg;
    std::string key;
    int counter;
    std::string iv;
    std::string aad;
    std::string tag;
    std::string pt;
    std::string ct;
} test_vector_rfc7539_t;

void test_yaml_testvector_rfc7539() {
    _test_case.begin("RFC 7539 YAML");

    return_t ret = errorcode_t::success;

    auto lambda_yaml_rfc7539 = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_rfc7539_t entry;

            entry.item = item["item"].as<std::string>("");
            entry.alg = item["alg"].as<std::string>("");
            entry.key = item["key"].as<std::string>("");
            entry.counter = item["counter"].as<int>();
            entry.iv = item["iv"].as<std::string>("");
            entry.aad = item["aad"].as<std::string>("");
            entry.tag = item["tag"].as<std::string>("");
            entry.pt = item["pt"].as<std::string>("");
            entry.ct = item["ct"].as<std::string>("");

            binary_t key = base16_decode_rfc(entry.key);
            uint32 counter = entry.counter;
            binary_t iv = base16_decode_rfc(entry.iv);
            binary_t pt = to_binary(entry.pt);
            binary_t aad = base16_decode_rfc(entry.aad);
            binary_t ct = base16_decode_rfc(entry.ct);
            binary_t tag = base16_decode_rfc(entry.tag);

            openssl_crypt crypt;
            binary_t c;
            binary_t n;
            binary_t p;
            binary_t t;

            openssl_chacha20_iv(n, counter, iv);

            ret = crypt.encrypt(entry.alg, key, n, pt, c, aad, t);
            if (errorcode_t::success == ret) {
                if ((t != tag) || (c != ct)) {
                    ret = errorcode_t::mismatch;
                }
            }
            _test_case.test(ret, __FUNCTION__, "%s", entry.item.c_str());

            if (errorcode_t::success == ret) {
                ret = crypt.decrypt(entry.alg, key, n, ct, p, aad, tag);
                _test_case.assert(p == pt, __FUNCTION__, "%s", entry.item.c_str());
            }

            if (entry.alg == "chacha20-poly1305") {
                c.clear();
                p.clear();
                t.clear();

                crypto_aead_builder builder;
                auto aead = builder.set_scheme(crypto_scheme_t::tls_chacha20_poly1305).build();
                if (aead) {
                    ret = aead->encrypt(key, n, pt, c, aad, t);
                    _logger->hdump("> ciphertext", c, 16, 3);
                    _test_case.assert(tag == t, __FUNCTION__, "#tag");
                    _test_case.assert(ct == c, __FUNCTION__, "#expect");
                    _test_case.test(ret, __FUNCTION__, "#encrypt");

                    ret = aead->decrypt(key, n, ct, p, aad, t);
                    _logger->hdump("> plaintext", p, 16, 3);
                    _test_case.test(ret, __FUNCTION__, "#decrypt");

                    aead->release();
                }
            }
        }
    };

    yaml_testcase test;
    test.add("RFC 7539", lambda_yaml_rfc7539).run("testvector_rfc7539.yml");
}

void testcase_testvector_rfc7539() { test_yaml_testvector_rfc7539(); }
