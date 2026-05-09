/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_record_ack.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_ack_len[] = "ack len";
constexpr char constexpr_ack[] = "record ack";

tls_record_ack::tls_record_ack(tls_session* session) : tls_record(tls_content_type_ack, session) {}

tls_record_ack::~tls_record_ack() {}

return_t tls_record_ack::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .run_trycatch([&]() -> return_t {
            uint16 len = get_body_size();
#if defined DEBUG
            uint16 ack_len = 0;
#endif
            binary_t ack;
            payload pl;

            // RFC 9147 7.  ACK Message
            // struct {
            //     RecordNumber record_numbers<0..2^16-1>;
            // } ACK;

            pl << new payload_member(uint16(0), true, constexpr_ack_len)  //
               << new payload_member(binary_t(), constexpr_ack);
            pl.set_reference_value(constexpr_ack, constexpr_ack_len);

            auto rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

#if defined DEBUG
            ack_len = pl.t_value_of<uint16>(constexpr_ack_len);
#endif
            pl.get_binary(constexpr_ack, ack);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_record, [&](basic_stream& dbs) -> void {
                    dbs.println("> %s %04x(%i)", constexpr_ack_len, ack_len, ack_len);
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(ack, &dbs, 16, 3, 0x0, dump_notrunc);
                    }
                });
            }
#endif
            pos += len;

            return success;
        });
    return pipeline.result();
}

return_t tls_record_ack::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline.run_trycatch([&]() -> return_t {
        payload pl;
        pl << new payload_member(uint16(0), true);
        return pl.write(bin);
    });
    return pipeline.result();
}

}  // namespace net
}  // namespace hotplace
