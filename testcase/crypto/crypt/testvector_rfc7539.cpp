/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   test_yaml_testvector_rfc7539.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

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

    YAML::Node testvector = YAML::LoadFile("./testvector_rfc7539.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto items = example["items"];
            for (const auto& item : items) {
                test_vector_rfc7539_t entry;

                entry.item = std::move(item["item"].as<std::string>());
                entry.alg = std::move(item["alg"].as<std::string>());
                entry.key = std::move(item["key"].as<std::string>());
                entry.counter = std::move(item["counter"].as<int>());
                entry.iv = std::move(item["iv"].as<std::string>());
                entry.aad = std::move(item["aad"].as<std::string>());
                entry.tag = std::move(item["tag"].as<std::string>());
                entry.pt = std::move(item["pt"].as<std::string>());
                entry.ct = std::move(item["ct"].as<std::string>());

                binary_t key = std::move(base16_decode_rfc(entry.key));
                uint32 counter = entry.counter;
                binary_t iv = std::move(base16_decode_rfc(entry.iv));
                binary_t pt = std::move(str2bin(entry.pt));
                binary_t aad = std::move(base16_decode_rfc(entry.aad));
                binary_t ct = std::move(base16_decode_rfc(entry.ct));
                binary_t tag = std::move(base16_decode_rfc(entry.tag));

                openssl_crypt crypt;
                binary_t c;
                binary_t n;
                binary_t p;
                binary_t t;

                openssl_chacha20_iv(n, counter, iv);

                ret = crypt.encrypt(entry.alg.c_str(), key, n, pt, c, aad, t);
                if (errorcode_t::success == ret) {
                    if ((t != tag) || (c != ct)) {
                        ret = errorcode_t::mismatch;
                    }
                }
                _test_case.test(ret, __FUNCTION__, "%s", entry.item.c_str());

                if (errorcode_t::success == ret) {
                    ret = crypt.decrypt(entry.alg.c_str(), key, n, ct, p, aad, tag);
                    _test_case.assert(p == pt, __FUNCTION__, "%s", entry.item.c_str());
                }

                if (entry.alg == "chacha20-poly1305") {
                    c.clear();
                    p.clear();
                    t.clear();

                    crypto_aead_builder builder;
                    auto aead = builder.set_scheme(crypto_scheme_tls_chacha20_poly1305).build();
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
        }
    }
}

void testcase_testvector_rfc7539() { test_yaml_testvector_rfc7539(); }
