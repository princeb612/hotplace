/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_hpack.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @remarks
 *      RFC 7541 HPACK: Header Compression for HTTP/2
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/net/sample.hpp>

// test/tls/http/http2.pcapng
// wireshark
// decode 'Header Block Fragment'

void test_h2() {
    _test_case.begin("HTTP/2 Header Compression");
    // const OPTION& option = _cmdline->value();

    // [test vector] chrome generated header

    auto lambda_decode = [&](hpack_dynamic_table* sess, std::multimap<std::string, std::string>& kv, const binary_t bin) -> void {
        size_t pos = 0;
        std::string name;
        std::string value;
        while (pos < bin.size()) {
            encoder->decode_header(sess, bin.data(), bin.size(), pos, name, value);
            kv.emplace(name, value);
            _logger->writeln("> %s: %s", name.c_str(), value.c_str());
            sess->commit();
        }
    };

    auto lambda_test = [&](const char* text, hpack_dynamic_table* sess, const binary_t& bin, const std::multimap<std::string, std::string>& ekv) -> void {
        _logger->writeln(text);

        std::multimap<std::string, std::string> kv;
        lambda_decode(sess, kv, bin);

        sess->dump("dynamic table", dump_hpack_session_routine);

        for (const auto& item : kv) {
            const auto& k = item.first;
            const auto& v = item.second;
            _logger->writeln("%s: %s", k.c_str(), v.c_str());
        }
        _test_case.assert(kv == ekv, __FUNCTION__, "decode");
    };

    hpack_dynamic_table hpack_dyntable;

    auto lambda_hpack = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_item = item["item"].as<std::string>("");
                auto text_hpack = item["hpack"].as<std::string>("");

                auto bin = base16_decode_rfc(text_hpack);
                std::multimap<std::string, std::string> kv;

                auto node_kv = item["keyvalue"];
                if (node_kv && node_kv.IsMap()) {
                    for (auto node_pair : node_kv) {
                        auto key_node = node_pair.first;
                        auto value_node = node_pair.second;
                        auto key = key_node.as<std::string>("");
                        auto value = value_node.as<std::string>("");
                        kv.emplace(key, value);
                    }
                }

                lambda_test(text_item.c_str(), &hpack_dyntable, bin, kv);
            }
        }
    };

    yaml_testcase test;
    test.add("HPACK", lambda_hpack).run("testvector_hpack.yml");
}

void testcase_testvector_hpack() { test_h2(); }
