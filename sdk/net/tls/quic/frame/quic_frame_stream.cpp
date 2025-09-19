/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame_stream::quic_frame_stream(tls_session* session, uint8 type) : quic_frame((quic_frame_t)type, session), _stream_id(0) {
    if ((quic_frame_type_stream <= type) && (type <= quic_frame_type_stream7)) {
    } else {
        throw exception(bad_request);
    }
}

uint8 quic_frame_stream::get_flags() { return (quic_frame_stream_mask & get_type()); }

uint64 quic_frame_stream::get_streamid() { return _stream_id; }

void quic_frame_stream::set(uint64 stream_id, uint8 unitype) { _stream_id = stream_id; }

quic_frame_stream& quic_frame_stream::set(const binary_t& bin) {
    _stream_data = bin;
    return *this;
}

}  // namespace net
}  // namespace hotplace
