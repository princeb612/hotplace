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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_ack_len[] = "ack len";
constexpr char constexpr_ack[] = "record ack";

tls_record_ack::tls_record_ack(tls_session* session) : tls_record(tls_content_type_ack, session) {}

tls_record_ack::~tls_record_ack() {}

return_t tls_record_ack::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        // RFC 9147 7.  ACK Message
        // struct {
        //     RecordNumber record_numbers<0..2^16-1>;
        // } ACK;

        uint16 ack_len = 0;
        binary_t ack;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_ack_len)  //
               << new payload_member(binary_t(), constexpr_ack);
            pl.set_reference_value(constexpr_ack, constexpr_ack_len);
            pl.read(stream, size, pos);

            ack_len = pl.t_value_of<uint16>(constexpr_ack_len);
            pl.get_binary(constexpr_ack, ack);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> %s %04x(%i)", constexpr_ack_len, ack_len, ack_len);
            if (check_trace_level(loglevel_debug)) {
                dump_memory(ack, &dbs, 16, 3, 0x0, dump_notrunc);
            }

            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif

        pos += len;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record_ack::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    {
        payload pl;
        pl << new payload_member(uint16(0), true);
        pl.write(bin);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
