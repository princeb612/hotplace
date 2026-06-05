/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_rfc7919.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

struct test_vector_rfc7919_t {
    std::string item;
    std::string group;
    binary_t p;
    binary_t q;
    binary_t g;
};

void test_yaml_testvector_rfc7919() {
    _test_case.begin("RFC 7919");

    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto lambda_yaml_rfc7919 = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        crypto_key key;
        crypto_keychain keychain;
        for (const auto& item : items) {
            test_vector_rfc7919_t entry;

            entry.item = item["item"].as<std::string>("");
            entry.group = item["group"].as<std::string>("");
            auto p = item["p"].as<std::string>("");
            auto q = item["q"].as<std::string>("");
            auto g = item["g"].as<std::string>("");
            entry.p = base16_decode_rfc(p);
            entry.q = base16_decode_rfc(q);
            entry.g = base16_decode_rfc(g);

            keydesc desc(entry.item);
            auto nid = advisor->nidof_name(entry.group);
            auto ret = keychain.add_dh(&key, nid, entry.p, entry.q, entry.g, binary_t{}, std::move(desc));
            _test_case.test(ret, __FUNCTION__, "%s", entry.item.c_str());

            auto pkey = key.find(entry.item.c_str());

            crypto_kty_t kty = crypto_kty_t::kty_unknown;
            crypt_datamap_t datamap;
            crypto_key::extract(pkey, public_key | private_key, kty, datamap, false);  // do not preserve leading zero octects to compare

            _test_case.assert(datamap[crypt_item_t::dh_p] == entry.p, __FUNCTION__, "check p");
            _test_case.assert(datamap[crypt_item_t::dh_q] == entry.q, __FUNCTION__, "check q");
            _test_case.assert(datamap[crypt_item_t::dh_g] == entry.g, __FUNCTION__, "check g");
        }

        auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
            _logger->write([&](basic_stream& bs) -> void {
                bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
                dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
            });
        };
        key.for_each(dump_crypto_key, nullptr);
        _test_case.assert(true, __FUNCTION__, "dump key");
    };

    yaml_testcase test;
    test.add("RFC 7919", lambda_yaml_rfc7919).run("testvector_rfc7919.yml");
}

void testcase_testvector_rfc7919() { test_yaml_testvector_rfc7919(); }
