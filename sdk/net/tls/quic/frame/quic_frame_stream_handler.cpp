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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream_handler.hpp>

namespace hotplace {
namespace net {

quic_frame_stream_handler::quic_frame_stream_handler(tls_session* session) : _session(nullptr) {
    if (nullptr == session) {
        throw exception(no_session);
    }
    _session = session;
    _shared.make_share(this);
}

quic_frame_stream_handler::~quic_frame_stream_handler() {}

return_t quic_frame_stream_handler::read(uint64 streamid) {
    return_t ret = errorcode_t::success;
    return ret;
}

void quic_frame_stream_handler::addref() { _shared.addref(); }

void quic_frame_stream_handler::release() { _shared.delref(); }

tls_session* quic_frame_stream_handler::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
