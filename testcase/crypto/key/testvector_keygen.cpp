/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_keygen.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_yaml_testvector_keygen() {
    _test_case.begin("keygen");

    // sketch

    crypto_key key;
    auto advisor = crypto_advisor::get_instance();
    struct keyitem {
        std::string kty;
        std::string kid;
    };
    std::list<keyitem> keyitems;

    auto lambda_yaml_keygen = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                std::string text_itm = item["item"].as<std::string>("");
                std::string text_kty = item["kty"].as<std::string>("");
                std::string text_kid = item["kid"].as<std::string>("");
                auto node_param = item["param"];

                keyitem kitem;
                kitem.kty = text_kty;
                kitem.kid = text_kid;
                keyitems.push_back(kitem);

                crypto_keygen keygen(&key, text_kty, encoding_t::encoding_base16rfc);
                keygen.set(keydesc(text_kid));
                if (node_param && node_param.IsMap()) {
                    for (auto node_pair : node_param) {
                        auto key_node = node_pair.first;
                        auto value_node = node_pair.second;

                        auto key = key_node.as<std::string>("");
                        if (key == "ybit") {
                            auto ybit = key_node.as<bool>(false);
                            keygen.set(key.c_str(), ybit);
                        } else {
                            auto value = value_node.as<std::string>("");
                            keygen.set(key.c_str(), value.c_str());
                        }
                    }
                    keygen.build();
                } else {
                    keygen.gen();
                }
            }
        }
    };

    yaml_testcase test;
    test.add("KEY GEN", lambda_yaml_keygen).run("testvector_keygen.yml");

    std::map<std::string, bool> keymap;
    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        keymap.emplace(item->get_desc().get_kid_str(), true);

        auto pkey = item->get_pkey();

        _logger->write([&](basic_stream& bs) -> void {
            bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
            dump_key(pkey, &bs, 16, 3, dump_notrunc);
        });
    };
    key.for_each(dump_crypto_key, nullptr);

    auto lambda_check = [&](const char* function, const std::string& ktyname, const std::string& kid) -> void {
        auto pkey = key.find(kid.c_str());
        auto nid = advisor->nidof_name(ktyname);

        crypto_kty_t kty = {};
        uint32 id = 0;
        advisor->ktyof_evp_pkey(pkey, kty, id);

        _test_case.assert(keymap[kid] && (nid == id), function, "kid [%s] nid %u %u", kid.c_str(), nid, id);
    };
    for (const auto& kitem : keyitems) {
        lambda_check(__FUNCTION__, kitem.kty, kitem.kid);
    }
}

void testcase_testvector_keygen() { test_yaml_testvector_keygen(); }
