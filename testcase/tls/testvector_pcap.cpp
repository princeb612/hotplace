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

void play_yaml_pcap(const char* filename) {
    auto sslkeylog = sslkeylog_importer::get_instance();

    bool has_fatal = false;
    auto lambda_test_fatal_alert = [&](uint8 level, uint8 desc) -> void {
        if (tls_alertlevel_fatal == level) {
            if (tls_alertdesc_certificate_unknown != desc) {
                has_fatal = true;
            }
        }
    };

    auto lambda_yaml_pcap = [&](const YAML::Node& example) -> void {
        __try2 {
            auto protocol = example["protocol"].as<std::string>();

            session_type_t session_type = session_type_tls;
            if (protocol == "TLS") {
                session_type = session_type_tls;
            } else if (protocol == "DTLS") {
                session_type = session_type_dtls;
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format - reason: protocol");
                __leave2;
            }

            tls_session session(session_type);

            sslkeylog->clear();
            sslkeylog->attach(&session);

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
                    std::string record = item["record"].as<std::string>();

                    tls_direction_t direction;
                    if (dir == "from_client") {
                        direction = from_client;
                    } else if (dir == "from_server") {
                        direction = from_server;
                    } else {
                        _test_case.assert(false, __FUNCTION__, "bad message format - reason: dir");
                        break;
                    }

                    binary_t bin_record = base16_decode(record);
                    if (bin_record.empty()) {
                        continue;
                    }
                    dump_record(text.c_str(), &session, direction, bin_record);

                    session.get_alert(direction, lambda_test_fatal_alert);
                    if (has_fatal) {
                        _test_case.test(failed, __FUNCTION__, "fatal alert");
                        break;
                    }
                }
            }
        }
        __finally2 {}
    };

    YAML::Node testvector = YAML::LoadFile(filename);
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _test_case.begin(text_example);

            auto schema = example["schema"].as<std::string>();

            if (schema == "PCAP SIMPLE") {
                lambda_yaml_pcap(example);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format - reason: schema");
            }
        }
    }
}

void test_yaml_testvector_pcap() {
    play_yaml_pcap("testvector_pcap_tls13.yml");
    play_yaml_pcap("testvector_pcap_tls12.yml");
    play_yaml_pcap("testvector_pcap_http.yml");
    play_yaml_pcap("testvector_pcap_dtls12.yml");
    play_yaml_pcap("testvector_pcap_tls13_mlkem.yml");
}

void testcase_testvector_pcap() { test_yaml_testvector_pcap(); }
