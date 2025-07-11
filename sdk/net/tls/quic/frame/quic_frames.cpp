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
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

quic_frames::quic_frames(quic_packet* packet) : _packet(packet) {
    if (nullptr == packet) {
        throw exception(not_specified);
    }
    packet->addref();
}

quic_frames::~quic_frames() {
    clear();
    get_packet()->release();
}

return_t quic_frames::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto packet = get_packet();

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
        auto lambda = [&](quic_frame* frame) -> void { frame->write(dir, bin); };
        for_each(lambda);
    }
    __finally2 {}
    return ret;
}

return_t quic_frames::add(quic_frame* frame, bool upref) {
    return_t ret = errorcode_t::success;
    if (frame) {
        if (upref) {
            frame->addref();
        }

        critical_section_guard guard(_lock);

        auto type = frame->get_type();
        auto iter = _dictionary.find(type);
        if (_dictionary.end() == iter) {
            _dictionary.insert({type, frame});
            _frames.push_back(frame);
        } else {
            frame->release();
            ret = errorcode_t::already_exist;
        }
    }
    return ret;
}

quic_frames& quic_frames::operator<<(quic_frame* frame) {
    add(frame);
    return *this;
}

void quic_frames::for_each(std::function<void(quic_frame*)> func) {
    if (func) {
        critical_section_guard guard(_lock);
        for (auto item : _frames) {
            func(item);
        }
    }
}

quic_frame* quic_frames::get(uint8 type, bool upref) {
    quic_frame* obj = nullptr;
    critical_section_guard guard(_lock);
    auto iter = _dictionary.find(type);
    if (_dictionary.end() != iter) {
        obj = iter->second;
        if (upref) {
            obj->addref();
        }
    }
    return obj;
}

quic_frame* quic_frames::getat(size_t index, bool upref) {
    quic_frame* obj = nullptr;
    critical_section_guard guard(_lock);
    if (index < _frames.size()) {
        obj = _frames[index];
    }
    return obj;
}

size_t quic_frames::size() { return _frames.size(); }

void quic_frames::clear() {
    critical_section_guard guard(_lock);
    for (auto item : _frames) {
        item->release();
    }
    _frames.clear();
    _dictionary.clear();
}

quic_packet* quic_frames::get_packet() { return _packet; }

}  // namespace net
}  // namespace hotplace
