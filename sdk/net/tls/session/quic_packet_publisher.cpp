/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/trial/tls_composer.hpp>
#include <sdk/net/tls/quic_packet_publisher.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_packet_publisher::quic_packet_publisher() {}

quic_packet_publisher::~quic_packet_publisher() {}

quic_packet_publisher& quic_packet_publisher::add(tls_hs_type_t type, std::function<return_t(tls_handshake*, tls_direction_t)> hook) {
    critical_section_guard guard(_lock);
    handshake_t item;
    item.type = type;
    item.hook = hook;
    _handshakes.push(item);
    return *this;
}

quic_packet_publisher& quic_packet_publisher::add(const binary_t& stream) {
    // HTTP/3 Stream
    critical_section_guard guard(_lock);
    _queue.push(stream);
    return *this;
}

quic_packet_publisher& quic_packet_publisher::ack(protection_level_t level, uint64 pkn) {
    critical_section_guard guard(_lock);
    auto& bucket = _ack[level];
    bucket.add(pkn);
    return *this;
}

quic_packet_publisher& quic_packet_publisher::operator<<(tls_hs_type_t handshake) { return add(handshake, nullptr); }

quic_packet_publisher& quic_packet_publisher::operator<<(const binary_t& stream) { return add(stream); }

return_t quic_packet_publisher::publish(tls_session* session, tls_direction_t dir, std::function<return_t(quic_packet*, tls_session*, tls_direction_t)> func) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    while (false == _handshakes.empty()) {
        const auto& item = _handshakes.front();

        tls_handshake* handshake = nullptr;
        switch (item.type) {
            case tls_hs_client_hello: {
                ret = tls_composer::construct_client_hello(&handshake, session, item.hook, tls_13, tls_13);
            } break;
            case tls_hs_server_hello: {
                ret = tls_composer::construct_server_hello(&handshake, session, item.hook, tls_13, tls_13);
            } break;
        }

        _handshakes.pop();
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
