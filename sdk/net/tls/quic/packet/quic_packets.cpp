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
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <sdk/net/tls/quic/packet/quic_packets.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

quic_packets::quic_packets() {}

quic_packets::~quic_packets() { clear(); }

return_t quic_packets::read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (pos < size) {
            auto msb = stream[pos];
            quic_packet_builder builder;
            auto packet = builder.set_msb(msb).set_session(session).build();
            if (packet) {
                ret = packet->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    add(packet);
                } else {
                    packet->release();
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

return_t quic_packets::read(tls_session* session, tls_direction_t dir, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const byte_t* stream = &bin[0];
        size_t size = bin.size();
        size_t pos = 0;
        auto ret = read(session, dir, stream, size, pos);
    }
    __finally2 {}
    return ret;
}

return_t quic_packets::write(tls_session* session, tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto lambda = [&](quic_packet* packet) -> void { packet->write(dir, bin); };
        for_each(lambda);
    }
    __finally2 {}
    return ret;
}

return_t quic_packets::add(quic_packet* packet, bool upref) {
    return_t ret = errorcode_t::success;
    if (packet) {
        if (upref) {
            packet->addref();
        }

        critical_section_guard guard(_lock);

        _packets.push_back(packet);
    }
    return ret;
}

quic_packets& quic_packets::operator<<(quic_packet* packet) {
    add(packet);
    return *this;
}

void quic_packets::for_each(std::function<void(quic_packet*)> func) {
    if (func) {
        critical_section_guard guard(_lock);
        for (auto item : _packets) {
            func(item);
        }
    }
}

quic_packet* quic_packets::getat(size_t index, bool upref) {
    quic_packet* obj = nullptr;
    critical_section_guard guard(_lock);
    if (index < _packets.size()) {
        obj = _packets[index];
    }
    return obj;
}

size_t quic_packets::size() { return _packets.size(); }

void quic_packets::clear() {
    critical_section_guard guard(_lock);
    for (auto item : _packets) {
        item->release();
    }
    _packets.clear();
}

}  // namespace net
}  // namespace hotplace
