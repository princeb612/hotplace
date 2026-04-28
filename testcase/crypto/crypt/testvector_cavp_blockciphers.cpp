/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_cavp_blockciphers.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

typedef struct _test_vector_nist_cavp_blockcipher_t {
    std::string item;
    std::string alg;
    std::string key;
    std::string iv;
    std::string pt;
    std::string ct;
} test_vector_nist_cavp_blockcipher_t;

void test_yaml_cavp_blockciphers() {
    _test_case.begin("CAVP block cipher YAML");

    openssl_crypt crypt;

    auto lambda_test_cavp_block_ciphers = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_nist_cavp_blockcipher_t entry;
            entry.item = std::move(item["item"].as<std::string>());
            entry.alg = std::move(item["alg"].as<std::string>());
            entry.key = std::move(item["key"].as<std::string>());
            entry.iv = std::move(item["iv"].as<std::string>());
            entry.pt = std::move(item["pt"].as<std::string>());
            entry.ct = std::move(item["ct"].as<std::string>());

            binary_t ciphertext;
            binary_t plaintext;
            crypt_context_t* handle = nullptr;
            crypt.open(&handle, entry.alg, base16_decode(entry.key), base16_decode(entry.iv));
            crypt.set(handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
            crypt.encrypt(handle, base16_decode(entry.pt), ciphertext);
            crypt.decrypt(handle, base16_decode(entry.ct), plaintext);
            crypt.close(handle);

            _logger->hdump("CT", ciphertext);
            _logger->hdump("PT", plaintext);

            _test_case.assert(base16_decode(entry.ct) == ciphertext, __FUNCTION__, "%s - encrypt", entry.item.c_str());
            _test_case.assert(base16_decode(entry.pt) == plaintext, __FUNCTION__, "%s - decrypt", entry.item.c_str());
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_cavp_blockciphers.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "BLOCK CIPHERS") {
                lambda_test_cavp_block_ciphers(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_cavp_blockciphers() {
    test_yaml_cavp_blockciphers();  // validate wrapper class openssl_crypt
}
