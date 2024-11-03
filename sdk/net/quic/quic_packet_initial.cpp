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

quic_packet_initial::quic_packet_initial() : quic_packet(), _length(0), _pn(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs) : quic_packet(rhs), _length(rhs._length), _pn(rhs._pn) {}

return_t quic_packet_initial::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = quic_packet::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // size_t initial_offset = pos;

        uint8 pn_length = get_pn_length();
        payload pl;
        pl << new payload_member(new quic_integer(binary_t()), "token") << new payload_member(new quic_integer(int(0)), "length")
           << new payload_member(binary_t(), "pn") << new payload_member(binary_t(), "payload");
        pl.select("pn")->reserve(pn_length);
        pl.read(stream, size, pos);

        pl.select("token")->get_variant().to_binary(_token);
        _length = pl.select("length")->get_payload_encoded()->value();
        binary_t bin_pn;
        pl.select("pn")->get_variant().to_binary(bin_pn);  // 8..32
        _pn = binary_to_intger_force<uint32>(bin_pn);
        pl.select("payload")->get_variant().to_binary(_payload);

        // size_t pn_offset = initial_offset + pl.offset_of("pn");
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::write(binary_t& packet) {
    return_t ret = errorcode_t::success;
    ret = quic_packet::write(packet);
    binary_append(packet, _token);
    binary_append(packet, _pn);
    binary_append(packet, _payload);
    return ret;
}

void quic_packet_initial::dump(stream_t* s) {
    if (s) {
        quic_packet::dump(s);
        // token
        s->printf(" > token\n");
        dump_memory(_token, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        // length
        s->printf(" > length %I64i\n", get_length());
        // pn
        s->printf(" > packet number %08x\n", get_packet_number());
        // payload
        s->printf(" > payload\n");
        dump_memory(_payload, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
    }
}

quic_packet_initial& quic_packet_initial::set_token(const binary_t& token) {
    set_binary(_token, token);
    return *this;
}

const binary_t& quic_packet_initial::get_token() { return _token; }

uint64 quic_packet_initial::get_length() { return _length; }

quic_packet_initial& quic_packet_initial::set_packet_number(uint32 pn) {
    _pn = pn;
    return *this;
}

uint32 quic_packet_initial::get_packet_number() { return _pn; }

quic_packet_initial& quic_packet_initial::set_payload(const binary_t& payload) {
    set_binary(_payload, payload);
    return *this;
}

quic_packet_initial& quic_packet_initial::set_payload(const byte_t* stream, size_t size) {
    set_binary(_payload, stream, size);
    return *this;
}

const binary_t& quic_packet_initial::get_payload() { return _payload; }

}  // namespace net
}  // namespace hotplace
