/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>

namespace hotplace {
namespace net {

http3_frame_builder::http3_frame_builder() : _type(h3_frame_data), _dyntable(nullptr) {}

http3_frame_builder& http3_frame_builder::set(h3_frame_t type) {
    _type = type;
    return *this;
}

http3_frame_builder& http3_frame_builder::set(qpack_dynamic_table* dyntable) {
    _dyntable = dyntable;
    return *this;
}

http3_frame* http3_frame_builder::build() {
    http3_frame* frame = nullptr;
    switch (_type) {
        case h3_frame_data: {
            __try_new_catch_only(frame, new http3_frame_data);
        } break;
        case h3_frame_headers: {
            __try_new_catch_only(frame, new http3_frame_headers(_dyntable));
        } break;
        case h3_frame_cancel_push: {
            __try_new_catch_only(frame, new http3_frame_cancel_push);
        } break;
        case h3_frame_settings: {
            __try_new_catch_only(frame, new http3_frame_settings);
        } break;
        case h3_frame_push_promise: {
            __try_new_catch_only(frame, new http3_frame_push_promise);
        } break;
        case h3_frame_goaway: {
            __try_new_catch_only(frame, new http3_frame_goaway);
        } break;
        case h3_frame_origin: {
            __try_new_catch_only(frame, new http3_frame_origin);
        } break;
        case h3_frame_max_push_id: {
            __try_new_catch_only(frame, new http3_frame_max_push_id);
        } break;
        case h3_frame_metadata: {
            __try_new_catch_only(frame, new http3_frame_metadata);
        } break;
        case h3_frame_priority_update:
        case h3_frame_priority_update1: {
            __try_new_catch_only(frame, new http3_frame_priority_update((h3_frame_t)_type));
        } break;
        default: {
            __try_new_catch_only(frame, new http3_frame_unknown(_type));
        } break;
    }
    return frame;
}

h3_frame_t http3_frame_builder::get_type() { return _type; }

}  // namespace net
}  // namespace hotplace
