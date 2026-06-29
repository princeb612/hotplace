/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_pcap.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void play_yaml_pcap_http3(const char* filename) {
    auto sslkeylog = sslkeylog_importer::get_instance();

    tls_session tlssession(session_type_t::tls);
    tls_session quicsession(session_type_t::quic);
    sslkeylog->clear();
    sslkeylog->attach(&tlssession);
    sslkeylog->attach(&quicsession);

    bool has_fatal = false;
    auto lambda_test_fatal_alert = [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            if (tls_alertdesc_t::certificate_unknown != desc) {
                has_fatal = true;
            }
        }
    };

    auto lambda_yaml_pcap = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        auto protocol = example["protocol"].as<std::string>("");

        if (protocol != "HTTP/3") {
            _test_case.assert(false, __FUNCTION__, "bad message format - reason: protocol");
            return;
        }

        auto secrets = example["secrets"];
        if (secrets && secrets.IsSequence()) {
            for (const auto& item : secrets) {
                (*sslkeylog) << item["item"].as<std::string>("");
            }
        }

        return_t ret = errorcode_t::success;
        for (const auto& item : items) {
            std::string text = item["item"].as<std::string>("");
            std::string dir = item["dir"].as<std::string>("");
            std::string protocol = item["protocol"].as<std::string>("");

            tls_direction_t direction;
            if (dir == "from_client") {
                direction = from_client;
            } else if (dir == "from_server") {
                direction = from_server;
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format - reason: dir");
                continue;
            }

            _logger->colorln(text);

            if (protocol == "QUIC") {
                std::string frame = item["frame"].as<std::string>("");
                binary_t bin_frame = base16_decode_rfc(frame);

                quic_packets packets;
                ret = packets.read(&quicsession, direction, bin_frame);

                quicsession.get_alert(direction, lambda_test_fatal_alert);
                if (has_fatal) {
                    _test_case.assert(false == has_fatal, __FUNCTION__, "fatal alert");
                    break;
                }
            } else if (protocol == "TLS 1.3") {
                // tls_records records;
                // ret = records.read(&tlssession, dir, bin_frame);
                ret = errorcode_t::do_nothing;
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format - reason: protocol");
                continue;
            }

            _test_case.test(ret, __FUNCTION__, "%s", text.c_str());
        }
    };

    yaml_testcase test;
    test.add("PCAP SIMPLE", lambda_yaml_pcap).run(filename);
}

void test_yaml_testvector_pcap_http3() { play_yaml_pcap_http3("testvector_pcap_http3.yml"); }

void testcase_testvector_pcap() { test_yaml_testvector_pcap_http3(); }
