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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ack.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_connection_close.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_handshake_done.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_new_connection_id.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_new_token.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ping.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_reset_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stop_sending.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

quic_frames::quic_frames() : _packet(nullptr) {}

quic_frames::quic_frames(quic_packet* packet) : _packet(packet) {}

return_t quic_frames::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto packet = get_packet();
        if (nullptr == packet) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (pos < size) {
            uint64 value = 0;
            auto tpos = pos;
            ret = quic_read_vle_int(stream, size, tpos, value);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            quic_frame_t type = (quic_frame_t)value;
            quic_frame_builder builder;
            auto frame = builder.set(type).set(packet).build();
            if (frame) {
                ret = frame->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    add(frame);
                } else {
                    frame->release();
                }
            } else {
                ret = errorcode_t::not_supported;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_frames::read(tls_direction_t dir, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        const byte_t* stream = &bin[0];
        size_t size = bin.size();
        size_t pos = 0;
        auto ret = read(dir, stream, size, pos);
    }
    __finally2 {}
    return ret;
}

return_t quic_frames::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == get_packet()) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto lambda = [&](quic_frame* frame) -> return_t { return frame->write(dir, bin); };
        for_each(lambda);
    }
    __finally2 {}
    return ret;
}

return_t quic_frames::add(quic_frame* frame, bool upref) { return _frames.add(frame, upref); }

quic_frames& quic_frames::operator<<(quic_frame* frame) {
    add(frame);
    return *this;
}

return_t quic_frames::for_each(std::function<return_t(quic_frame*)> func) { return _frames.for_each(func); }

quic_frame* quic_frames::get(uint8 type, bool upref) { return _frames.get(type, upref); }

quic_frame* quic_frames::getat(size_t index, bool upref) { return _frames.getat(index, upref); }

bool quic_frames::empty() { return _frames.empty(); }

size_t quic_frames::size() { return _frames.size(); }

void quic_frames::clear() { return _frames.clear(); }

quic_packet* quic_frames::get_packet() { return _packet; }

void quic_frames::set_packet(quic_packet* packet) { _packet = packet; }

bool quic_frames::is_significant() {
    bool ret = false;
    auto lambda = [&](quic_frame* frame) -> return_t {
        auto type = frame->get_type();
        switch (type) {
            case quic_frame_type_padding:
            case quic_frame_type_ack: {
            } break;
            default: {
                ret = true;
            } break;
        }
        return success;
    };
    for_each(lambda);
    return ret;
}

}  // namespace net
}  // namespace hotplace
