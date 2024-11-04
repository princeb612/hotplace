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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quic_packet_retry::quic_packet_retry() : quic_packet() {}

quic_packet_retry::quic_packet_retry(const quic_packet_retry& rhs) : quic_packet(rhs) {}

return_t quic_packet_retry::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = quic_packet::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // size_t initial_offset = pos;

        payload pl;
        pl << new payload_member(binary_t(), "retry token") << new payload_member(binary_t(), "retry integrity tag");
        pl.select("retry integrity tag")->reserve(128 >> 3);
        pl.read(stream, size, pos);

        pl.select("retry token")->get_variant().to_binary(_retry_token);
        pl.select("retry integrity tag")->get_variant().to_binary(_retry_integrity_tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_retry::write(binary_t& packet) {
    return_t ret = errorcode_t::success;
    ret = quic_packet::write(packet);

    payload pl;
    pl << new payload_member(_retry_token, "retry token") << new payload_member(_retry_integrity_tag, "retry integrity tag");
    pl.write(packet);

    return ret;
}

void quic_packet_retry::dump(stream_t* s) {
    if (s) {
        quic_packet::dump(s);

        s->printf(" > retry token\n");
        dump_memory(_retry_token, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
        s->printf(" > retry integrity tag\n");
        dump_memory(_retry_integrity_tag, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
    }
}

const binary_t quic_packet_retry::get_retry_token() { return _retry_token; }

const binary_t quic_packet_retry::get_integrity_tag() { return _retry_integrity_tag; }

}  // namespace net
}  // namespace hotplace
