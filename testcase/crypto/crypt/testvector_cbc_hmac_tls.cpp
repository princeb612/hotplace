/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_cbc_hmac_tls.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

// CBC-HMAC TLS
struct test_vector_cbchmac_tls_t {
    std::string item;
    std::string flag;
    std::string macalg;
    std::string enckey;
    std::string iv;
    std::string mackey;
    std::string aad;
    std::string pt;
    std::string ct;
};

void test_cbc_hmac(test_vector_cbchmac_tls_t* entry) {
    return_t ret = errorcode_t::success;
    crypto_cbc_hmac cbchmac;
    uint16 flag = 0;

    binary_t enckey = base16_decode(entry->enckey);
    binary_t iv = base16_decode(entry->iv);
    binary_t mackey = base16_decode(entry->mackey);
    binary_t aad = base16_decode(entry->aad);
    binary_t plaintext = base16_decode_rfc(entry->pt);
    binary_t ciphertext = base16_decode_rfc(entry->ct);
    basic_stream desc;

    if ("mac_then_encrypt" == entry->flag) {
        desc << entry->flag;
        flag = tls_mac_then_encrypt;
    } else if ("encrypt_then_mac" == entry->flag) {
        desc << entry->flag;
        flag = tls_encrypt_then_mac;
    }
    desc.printf(R"( "%s")", entry->item.c_str());

    cbchmac.set_enc(aes128).set_mac(entry->macalg).set_flag(flag);

    _logger->writeln("> enckey %s", base16_encode(enckey).c_str());
    _logger->writeln("> iv     %s", base16_encode(iv).c_str());
    _logger->writeln("> mackey %s", base16_encode(mackey).c_str());
    _logger->writeln("> aad    %s", base16_encode(aad).c_str());

    binary_t pt;
    ret = cbchmac.decrypt(enckey, mackey, iv, aad, ciphertext, pt);
    _test_case.test(ret, __FUNCTION__, "%s #decryption", desc.c_str());
    _logger->hdump("> ciphertext", ciphertext, 16, 2);
    _logger->writeln("  %s", base16_encode(ciphertext).c_str());
    _logger->hdump("> plaintext", pt, 16, 2);
    _logger->writeln("  %s", base16_encode(pt).c_str());
    _test_case.assert(plaintext == pt, __FUNCTION__, "%s #decryption", desc.c_str());

    binary_t ct;
    ret = cbchmac.encrypt(enckey, mackey, iv, aad, plaintext, ct);
    _test_case.test(ret, __FUNCTION__, "%s #encryption", desc.c_str());
    _logger->hdump("> plaintext", plaintext, 16, 2);
    _logger->writeln("  %s", base16_encode(plaintext).c_str());
    _logger->hdump("> ciphertext", ct, 16, 2);
    _logger->writeln("  %s", base16_encode(ct).c_str());
    ret = cbchmac.decrypt(enckey, mackey, iv, aad, ct, pt);
    _test_case.assert(plaintext == pt, __FUNCTION__, "%s #decryption", desc.c_str());
}

void test_yaml_testvector_cbc_hmac_tls() {
    _test_case.begin("CBC-HMAC TLS 1.2 YAML");

    auto lambda_yaml_cbchmac_tls = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_cbchmac_tls_t entry;

            entry.item = std::move(item["item"].as<std::string>());
            entry.flag = std::move(item["flag"].as<std::string>());
            entry.macalg = std::move(item["macalg"].as<std::string>());
            entry.enckey = std::move(item["enckey"].as<std::string>());
            entry.iv = std::move(item["iv"].as<std::string>());
            entry.mackey = std::move(item["mackey"].as<std::string>());
            entry.aad = std::move(item["aad"].as<std::string>());
            entry.pt = std::move(item["pt"].as<std::string>());
            entry.ct = std::move(item["ct"].as<std::string>());

            test_cbc_hmac(&entry);
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_cbc_hmac_tls.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "CBC-HMAC TLS") {
                lambda_yaml_cbchmac_tls(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_cbc_hmac_tls() { test_yaml_testvector_cbc_hmac_tls(); }
