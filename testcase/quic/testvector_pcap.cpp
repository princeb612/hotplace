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

#include <hotplace/testcase/tls/sample.hpp>

void play_yaml_pcap_http3(const char* filename) {
    auto sslkeylog = sslkeylog_importer::get_instance();

    tls_session tlssession(session_type_tls);
    tls_session quicsession(session_type_quic);
    sslkeylog->clear();
    sslkeylog->attach(&tlssession);
    sslkeylog->attach(&quicsession);

    bool has_fatal = false;
    auto lambda_test_fatal_alert = [&](uint8 level, uint8 desc) -> void {
        if (tls_alertlevel_fatal == level) {
            if (tls_alertdesc_certificate_unknown != desc) {
                has_fatal = true;
            }
        }
    };

    auto lambda_yaml_pcap = [&](const YAML::Node& example) -> void {
        return_t ret = errorcode_t::success;
        auto secrets = example["secrets"];
        if (secrets && secrets.IsSequence()) {
            for (const auto& item : secrets) {
                (*sslkeylog) << item["item"].as<std::string>();
            }
        }

        auto items = example["items"];
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                std::string text = item["item"].as<std::string>();
                std::string dir = item["dir"].as<std::string>();
                std::string protocol = item["protocol"].as<std::string>();

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
                    std::string frame = item["frame"].as<std::string>();
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
                    ret = do_nothing;
                } else {
                    _test_case.assert(false, __FUNCTION__, "bad message format - reason: protocol");
                    continue;
                }

                _test_case.test(ret, __FUNCTION__, "%s", text.c_str());
            }
        }
    };

    YAML::Node testvector = YAML::LoadFile(filename);
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _test_case.begin(text_example);

            auto schema = example["schema"].as<std::string>();
            auto protocol = example["protocol"].as<std::string>();

            if (protocol != "HTTP/3") {
                _test_case.assert(false, __FUNCTION__, "bad message format - reason: protocol");
                continue;
            }
            if (schema != "PCAP SIMPLE") {
                _test_case.assert(false, __FUNCTION__, "bad message format - reason: schema");
                continue;
            }

            lambda_yaml_pcap(example);
        }
    }
}

void test_yaml_testvector_pcap_http3() { play_yaml_pcap_http3("testvector_pcap_http3.yml"); }

void testcase_testvector_pcap() { test_yaml_testvector_pcap_http3(); }
