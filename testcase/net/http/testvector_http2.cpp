/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_http2.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/net/sample.hpp>

// test/tls/http/http2.pcapng
// wireshark

void test_yaml_testvector_http2() {
    _test_case.begin("HTTP/2");

    return_t ret = errorcode_t::success;
    auto svr_socket = new naive_tcp_server_socket;
    network_session session(svr_socket);
    t_mlfq<network_session> event_queue;
    network_protocol_group protocol_group;
    http2_session h2sess;
    auto http2_prot = new http2_protocol;

    protocol_group << http2_prot;

    auto lambda_test_http2 = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_item = item["item"].as<std::string>();
                auto text_frame = item["frame"].as<std::string>();

                binary_t frame = base16_decode_rfc(text_frame);

                // network_server::producer_routine
                // session.produce(&event_queue, frame.data(), frame.size());
                session.getstream()->produce(frame.data(), frame.size());

                // network_server::consumer_routine
                network_stream_data* buffer_object = nullptr;
                session.consume(&protocol_group, &buffer_object);
                while (buffer_object) {
                    auto content = buffer_object->content();
                    auto content_size = buffer_object->size();
                    http_request* request = nullptr;
                    binary_t bin_resp;
                    ret = h2sess.consume(content, content_size, &request, bin_resp);
                    _test_case.test(ret, __FUNCTION__, "consume %s", text_item.c_str());
                    if (request) {
                        request->release();
                    }

                    network_stream_data* temp = buffer_object;
                    buffer_object = buffer_object->next();
                    temp->release();
                }
            }
        }
    };

    yaml_testcase test;
    test.add("HTTP/2", lambda_test_http2).run("testvector_http2.yml");

    http2_prot->release();
    svr_socket->release();
}

void testcase_testvector_http2() { test_yaml_testvector_http2(); }
