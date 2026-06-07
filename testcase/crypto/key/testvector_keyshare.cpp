/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_keyshare.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

/*
void test_mlkem_keyuse_routine(tls_group_t group, const binary_t& share) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;

    auto hint = advisor->hintof_tls_group(group);
    if (hint) {
    } else {
        _test_case.test(errorcode_t::not_supported, __FUNCTION__, "unknown");
    }
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}
*/

void testcase_yaml_keyshare() {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto lambda_yaml_keyshare_mlkem = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                std::string text_itm = item["item"].as<std::string>("");
                std::string text_group = item["group"].as<std::string>("");
                std::string text_share = item["share"].as<std::string>("");

                auto hint = advisor->hintof_tls_group(text_group);
                if (nullptr == hint) {
                    _test_case.test(errorcode_t::bad_data, __FUNCTION__, "unknown %s", text_group.c_str());
                    continue;
                }

                if (0 == (hint->flags & tls_flag_hybrid)) {
                    _test_case.test(errorcode_t::bad_data, __FUNCTION__, "not hybrid %s", text_group.c_str());
                }

                auto group = hint->group;
                auto name = hint->name;
                auto share = base16_decode_rfc(text_share);

                crypto_keyexchange keyexchange;
                crypto_key key;

                auto ret = keyexchange.keystore(group, &key, "store", share);
                _test_case.test(ret, __FUNCTION__, "store %s", name);
                auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
                    auto kid = item->get_desc().get_kid_cstr();

                    _logger->write([&](basic_stream& bs) -> void {
                        bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", kid);
                        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
                    });
                };
                key.for_each(dump_crypto_key, nullptr);

                binary_t keycapsule;
                binary_t sharedsecret;
                ret = keyexchange.encaps(group, share, keycapsule, sharedsecret);
                _test_case.test(ret, __FUNCTION__, "encaps %s", name);
            }
        }
    };

    yaml_testcase test;
    test.add("CLIENT SHARE", lambda_yaml_keyshare_mlkem).run("testvector_keyshare.yml");
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_testvector_keyshare() { testcase_yaml_keyshare(); }
