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
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_ack(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        // RFC 9147 7.  ACK Message
        // struct {
        //     RecordNumber record_numbers<0..2^16-1>;
        // } ACK;

        constexpr char constexpr_ack_len[] = "ack len";
        constexpr char constexpr_ack[] = "record ack";
        constexpr char constexpr_record[] = "record";
        uint16 ack_len = 0;
        binary_t ack;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_ack_len) << new payload_member(binary_t(), constexpr_ack)
               << new payload_member(uint8(0), constexpr_record);
            pl.set_reference_value(constexpr_ack, constexpr_ack_len);
            pl.read(stream, size, pos);

            ack_len = t_to_int<uint16>(pl.select(constexpr_ack_len));
            pl.select(constexpr_ack)->get_variant().to_binary(ack);
        }

        {
            s->printf("> %s %04x(%i)\n", constexpr_ack_len, ack_len, ack_len);
            dump_memory(ack, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
