/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http3_frame_builder.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_builder.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_cancel_push.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_data.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_goaway.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_headers.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_max_push_id.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_metadata.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_origin.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_priority_update.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_push_promise.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_settings.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_unknown.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

http3_frame_builder::http3_frame_builder() : _type(h3_frame_data), _session(nullptr) {}

http3_frame_builder& http3_frame_builder::set(h3_frame_t type) {
    _type = type;
    return *this;
}

http3_frame_builder& http3_frame_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

http3_frame* http3_frame_builder::build() {
    http3_frame* frame = nullptr;
    switch (_type) {
        case h3_frame_data: {
            frame = new http3_frame_data;
        } break;
        case h3_frame_headers: {
            if (_session) {
                frame = new http3_frame_headers(_session);
            }
        } break;
        case h3_frame_cancel_push: {
            frame = new http3_frame_cancel_push;
        } break;
        case h3_frame_settings: {
            frame = new http3_frame_settings;
        } break;
        case h3_frame_push_promise: {
            frame = new http3_frame_push_promise;
        } break;
        case h3_frame_goaway: {
            frame = new http3_frame_goaway;
        } break;
        case h3_frame_origin: {
            frame = new http3_frame_origin;
        } break;
        case h3_frame_max_push_id: {
            frame = new http3_frame_max_push_id;
        } break;
        case h3_frame_metadata: {
            frame = new http3_frame_metadata;
        } break;
        case h3_frame_priority_update:
        case h3_frame_priority_update1: {
            frame = new http3_frame_priority_update((h3_frame_t)_type);
        } break;
        default: {
            frame = new http3_frame_unknown(_type);
        } break;
    }
    return frame;
}

h3_frame_t http3_frame_builder::get_type() { return _type; }

}  // namespace net
}  // namespace hotplace
