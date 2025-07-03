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
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

quic_frame_builder::quic_frame_builder() : _type(quic_frame_type_padding), _session(nullptr) {}

quic_frame_builder& quic_frame_builder::set(quic_frame_t type) {
    _type = type;
    return *this;
}

quic_frame_builder& quic_frame_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

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
            __try_new_catch_only(frame, new quic_frame_ack(session));
            frame->set_type(type);
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
            __try_new_catch_only(frame, new quic_frame_stream(session));
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
    if (frame) {
        frame->set_type(type);  // quic_frame_type_stream + 1, ...
    }
    return frame;
}

quic_frame_t quic_frame_builder::get_type() { return _type; }

tls_session* quic_frame_builder::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
