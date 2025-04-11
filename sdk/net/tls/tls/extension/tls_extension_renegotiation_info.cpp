/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc RFC 5746
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_renegotiation_info_length[] = "renegotiation_info len";
constexpr char constexpr_renegotiation_info[] = "renegotiation_info";

tls_extension_renegotiation_info::tls_extension_renegotiation_info(tls_session* session) : tls_extension(tls1_ext_renegotiation_info, session), _modes(0) {}

return_t tls_extension_renegotiation_info::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        payload pl;
        pl << new payload_member(uint8(0), constexpr_renegotiation_info_length)  //
           << new payload_member(binary_t(), constexpr_renegotiation_info);
        pl.set_reference_value(constexpr_renegotiation_info, constexpr_renegotiation_info_length);
        pl.read(stream, size, pos);

        uint8 len = 0;
        binary_t info;
        len = pl.t_value_of<uint8>(constexpr_renegotiation_info_length);
        pl.get_binary(constexpr_renegotiation_info, info);

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("   > %s %u", constexpr_renegotiation_info_length, len);
            dump_memory(info, &dbs, 16, 4, 0x0, dump_notrunc);
            trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_renegotiation_info::do_write_body(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t renegotiation_connection;
        payload pl;
        pl << new payload_member(uint8(renegotiation_connection.size()), constexpr_renegotiation_info_length)  //
           << new payload_member(renegotiation_connection, constexpr_renegotiation_info);
        pl.write(bin);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
