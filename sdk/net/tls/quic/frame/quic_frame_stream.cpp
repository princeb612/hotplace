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
// #include <sdk/base/stream/fragmentation.hpp>
// #include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame_stream::quic_frame_stream(tls_session* session, uint8 type) : quic_frame((quic_frame_t)type, session), _stream_id(0), _unitype(0) {
    if ((quic_frame_type_stream <= type) && (type <= quic_frame_type_stream7)) {
    } else {
        throw exception(bad_request);
    }
}

uint8 quic_frame_stream::get_flags() { return (quic_frame_stream_mask & get_type()); }

uint64 quic_frame_stream::get_streamid() { return _stream_id; }

uint8 quic_frame_stream::get_unistream_type() { return _unitype; }

quic_frame_stream& quic_frame_stream::set(uint64 stream_id, uint8 unitype) {
    _stream_id = stream_id;
    _unitype = unitype;
    return *this;
}

quic_frame_stream& quic_frame_stream::set(const binary_t& bin) {
    _stream_data = bin;
    return *this;
}

}  // namespace net
}  // namespace hotplace
