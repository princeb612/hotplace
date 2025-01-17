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
#include <sdk/net/tls1/record/tls_record_ack.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_ack_len[] = "ack len";
constexpr char constexpr_ack[] = "record ack";

tls_record_ack::tls_record_ack(tls_session* session) : tls_record(tls_content_type_ack, session) {}

return_t tls_record_ack::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        {
            // RFC 9147 7.  ACK Message
            // struct {
            //     RecordNumber record_numbers<0..2^16-1>;
            // } ACK;

            uint16 ack_len = 0;
            binary_t ack;
            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_ack_len) << new payload_member(binary_t(), constexpr_ack);
                pl.set_reference_value(constexpr_ack, constexpr_ack_len);
                pl.read(stream, size, pos);

                ack_len = pl.t_value_of<uint16>(constexpr_ack_len);
                pl.select(constexpr_ack)->get_variant().to_binary(ack);
            }

            if (debugstream) {
                debugstream->printf("> %s %04x(%i)\n", constexpr_ack_len, ack_len, ack_len);
                dump_memory(ack, debugstream, 16, 3, 0x0, dump_notrunc);
            }
        }

        if (debugstream) {
            //
        }

        pos += len;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record_ack::do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
