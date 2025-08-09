/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http2/http2_frame_alt_svc.hpp>
#include <sdk/net/http/http2/http2_frame_builder.hpp>
#include <sdk/net/http/http2/http2_frame_continuation.hpp>
#include <sdk/net/http/http2/http2_frame_data.hpp>
#include <sdk/net/http/http2/http2_frame_goaway.hpp>
#include <sdk/net/http/http2/http2_frame_headers.hpp>
#include <sdk/net/http/http2/http2_frame_ping.hpp>
#include <sdk/net/http/http2/http2_frame_priority.hpp>
#include <sdk/net/http/http2/http2_frame_push_promise.hpp>
#include <sdk/net/http/http2/http2_frame_rst_stream.hpp>
#include <sdk/net/http/http2/http2_frame_settings.hpp>
#include <sdk/net/http/http2/http2_frame_window_update.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_builder::http2_frame_builder() : _type(h2_frame_data), _table(nullptr) {}

http2_frame_builder& http2_frame_builder::set(h2_frame_t type) {
    _type = type;
    return *this;
}

http2_frame_builder& http2_frame_builder::set(uint8 type) {
    _type = type;
    return *this;
}

http2_frame_builder& http2_frame_builder::set(hpack_dynamic_table* table) {
    _table = table;
    return *this;
}

uint8 http2_frame_builder::get_type() { return _type; }

hpack_dynamic_table* http2_frame_builder::get_hpack_dynamic_table() { return _table; }

http2_frame* http2_frame_builder::build() {
    http2_frame* frame = nullptr;
    switch (get_type()) {
        case h2_frame_data: {
            __try_new_catch_only(frame, new http2_frame_data);
        } break;
        case h2_frame_headers: {
            __try_new_catch_only(frame, new http2_frame_headers);
        } break;
        case h2_frame_priority: {
            __try_new_catch_only(frame, new http2_frame_priority);
        } break;
        case h2_frame_rst_stream: {
            __try_new_catch_only(frame, new http2_frame_rst_stream);
        } break;
        case h2_frame_settings: {
            __try_new_catch_only(frame, new http2_frame_settings);
        } break;
        case h2_frame_push_promise: {
            __try_new_catch_only(frame, new http2_frame_push_promise);
        } break;
        case h2_frame_ping: {
            __try_new_catch_only(frame, new http2_frame_ping);
        } break;
        case h2_frame_goaway: {
            __try_new_catch_only(frame, new http2_frame_goaway);
        } break;
        case h2_frame_window_update: {
            __try_new_catch_only(frame, new http2_frame_window_update);
        } break;
        case h2_frame_continuation: {
            __try_new_catch_only(frame, new http2_frame_continuation);
        } break;
        case h2_frame_altsvc: {
            __try_new_catch_only(frame, new http2_frame_alt_svc);
        } break;
    }
    if (frame) {
        frame->set_hpack_session(get_hpack_dynamic_table());
    }
    return frame;
}

}  // namespace net
}  // namespace hotplace
