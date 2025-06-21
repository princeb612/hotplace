/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_http2() {
    _test_case.begin("HTTP/2");

    return_t ret = errorcode_t::success;
    network_session session(new naive_tcp_server_socket);
    t_mlfq<network_session> event_queue;
    network_protocol_group protocol_group;
    http2_session h2sess;

    protocol_group << new http2_protocol;

    for (auto i = 0; i < sizeof_testvector_h2; i++) {
        auto item = testvector_h2frame + i;
        binary_t frame = std::move(base16_decode_rfc(item->frame));

        // network_server::producer_routine
        // session.produce(&event_queue, &frame[0], frame.size());
        session.getstream()->produce(&frame[0], frame.size());

        // network_server::consumer_routine
        network_stream_data* buffer_object = nullptr;
        session.consume(&protocol_group, &buffer_object);
        while (buffer_object) {
            auto content = buffer_object->content();
            auto content_size = buffer_object->size();
            http_request* request = nullptr;
            binary_t bin_resp;
            ret = h2sess.consume(content, content_size, &request, bin_resp);
            _test_case.test(ret, __FUNCTION__, "consume %s", item->desc);
            if (request) {
                request->release();
            }

            network_stream_data* temp = buffer_object;
            buffer_object = buffer_object->next();
            temp->release();
        }
    }
}
