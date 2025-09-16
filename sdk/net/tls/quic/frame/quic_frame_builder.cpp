/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ack.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_connection_close.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_handshake_done.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_http3_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_new_connection_id.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_new_token.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ping.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_reset_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stop_sending.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame_builder::quic_frame_builder()
    : _type(quic_frame_type_padding), _session(nullptr), _dir(from_any), _streamid(0), _unitype(0), _packet(nullptr), _construct(false) {}

quic_frame_builder& quic_frame_builder::set(quic_frame_t type) {
    _type = type;
    return *this;
}

quic_frame_builder& quic_frame_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

quic_frame_builder& quic_frame_builder::set(tls_direction_t dir) {
    _dir = dir;
    return *this;
}

quic_frame_builder& quic_frame_builder::set(uint64 streamid, uint8 unitype) {
    _streamid = streamid;
    _unitype = unitype;
    return *this;
}

quic_frame_builder& quic_frame_builder::set(quic_packet* packet) {
    _packet = packet;
    return *this;
}

quic_frame_builder& quic_frame_builder::enable_alpn(const std::string& alpn) {
    _alpn = alpn;
    return *this;
}

quic_frame_builder& quic_frame_builder::construct() {
    _construct = true;
    return *this;
}

quic_frame_t quic_frame_builder::get_type() { return _type; }

tls_session* quic_frame_builder::get_session() { return _session; }

tls_direction_t quic_frame_builder::get_direction() { return _dir; }

uint64 quic_frame_builder::get_streamid() { return _streamid; }

quic_packet* quic_frame_builder::get_packet() { return _packet; }

bool quic_frame_builder::is_construct() { return _construct; }

quic_frame* quic_frame_builder::build() {
    quic_frame* frame = nullptr;
    uint64 type = get_type();
    auto session = get_session();
    switch (type) {
        case quic_frame_type_padding: {
            // RFC 9001 19.1.  PADDING Frames
            __try_new_catch_only(frame, new quic_frame_padding(session));
        } break;
        case quic_frame_type_ping: {
            // RFC 9001 19.2.  PING Frames
            __try_new_catch_only(frame, new quic_frame_ping(session));
        } break;
        case quic_frame_type_ack:
        case quic_frame_type_ack + 1: {
            // RFC 9001 19.3.  ACK Frames
            __try_new_catch_only(frame, new quic_frame_ack(session, type));
        } break;
        case quic_frame_type_reset_stream: {
            // 19.4.  RESET_STREAM Frames
            __try_new_catch_only(frame, new quic_frame_reset_stream(session));
        } break;
        case quic_frame_type_stop_sending: {
            // 19.5.  STOP_SENDING Frames
            __try_new_catch_only(frame, new quic_frame_stop_sending(session));
        } break;
        case quic_frame_type_crypto: {
            // 19.6.  CRYPTO Frames
            __try_new_catch_only(frame, new quic_frame_crypto(session));
        } break;
        case quic_frame_type_new_token: {
            // 19.7.  NEW_TOKEN Frames
            __try_new_catch_only(frame, new quic_frame_new_token(session));
        } break;
        case quic_frame_type_stream:
        case quic_frame_type_stream1:
        case quic_frame_type_stream2:
        case quic_frame_type_stream3:
        case quic_frame_type_stream4:
        case quic_frame_type_stream5:
        case quic_frame_type_stream6:
        case quic_frame_type_stream7: {
            // 19.8.  STREAM Frames
            if ((_alpn == "\x2h3") || is_kindof_h3(session)) {
                __try_new_catch_only(frame, new quic_frame_http3_stream(session, type));
            } else {
                __try_new_catch_only(frame, new quic_frame_stream(session, type));
            }
            quic_frame_stream* stream = (quic_frame_stream*)frame;
            stream->set(get_streamid(), _unitype);
        } break;
        case quic_frame_type_max_data:
            // Figure 33: MAX_DATA Frame Format
            break;
        case quic_frame_type_max_stream_data:
            // Figure 34: MAX_STREAM_DATA Frame Format
            break;
        case quic_frame_type_max_streams:
            // Figure 35: MAX_STREAMS Frame Format
            break;
        case quic_frame_type_data_blocked:
            // Figure 36: DATA_BLOCKED Frame Format
            break;
        case quic_frame_type_stream_data_blocked:
            // Figure 37: STREAM_DATA_BLOCKED Frame Format
            break;
        case quic_frame_type_stream_blocked:
            // Figure 38: STREAMS_BLOCKED Frame Format
            break;
        case quic_frame_type_new_connection_id:
            // Figure 39: NEW_CONNECTION_ID Frame Format
            __try_new_catch_only(frame, new quic_frame_new_connection_id(session));
            break;
        case quic_frame_type_retire_connection_id:
            // Figure 40: RETIRE_CONNECTION_ID Frame Format
            break;
        case quic_frame_type_path_challenge:
            // Figure 41: PATH_CHALLENGE Frame Format
            break;
        case quic_frame_type_path_response:
            // Figure 42: PATH_RESPONSE Frame Format
            break;
        case quic_frame_type_connection_close:
        case quic_frame_type_connection_close1:
            // Figure 43: CONNECTION_CLOSE Frame Format
            __try_new_catch_only(frame, new quic_frame_connection_close(session));
            break;
        case quic_frame_type_handshake_done:
            // Figure 44: HANDSHAKE_DONE Frame Format
            __try_new_catch_only(frame, new quic_frame_handshake_done(session));
            break;
        default: {
        } break;
    }
    return frame;
}

}  // namespace net
}  // namespace hotplace
