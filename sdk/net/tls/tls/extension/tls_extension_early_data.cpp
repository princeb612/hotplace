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

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_early_data.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

const char constexpr_max_early_data_size[] = "max early data size";
const char constexpr_new_session_ticket[] = "new session ticket";

tls_extension_early_data::tls_extension_early_data(tls_session* session, tls_hs_type_t hs) : tls_extension(tls_ext_early_data, session), _hs(hs) {}

return_t tls_extension_early_data::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.10.  Early Data Indication
        // struct {
        //     select (Handshake.msg_type) {
        //         case new_session_ticket:   uint32 max_early_data_size;
        //         case client_hello:         Empty;
        //         case encrypted_extensions: Empty;
        //     };
        // } EarlyDataIndication;

        auto session = get_session();
        auto& protection = session->get_tls_protection();

        // RFC 8446 Early data is not permitted after a HelloRetryRequest
        if (tls_flow_hello_retry_request == protection.get_flow()) {
            __leave2;
        }

        {
            bool is_new_session_ticket = (tls_hs_new_session_ticket == get_handshake_type());
            uint32 max_early_data_size = 0;

            payload pl;
            pl << new payload_member(uint32(0), true, constexpr_max_early_data_size, constexpr_new_session_ticket);

            pl.set_group(constexpr_new_session_ticket, is_new_session_ticket);

            pl.read(stream, size, pos);

            if (is_new_session_ticket) {
                max_early_data_size = pl.t_value_of<uint32>(constexpr_max_early_data_size);
#if defined DEBUG
                if (istraceable()) {
                    basic_stream dbs;
                    dbs.println("  > %s 0x%04x(%i)", constexpr_max_early_data_size, max_early_data_size, max_early_data_size);
                    trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
                }
#endif
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_early_data::do_write_body(binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

tls_hs_type_t tls_extension_early_data::get_handshake_type() { return _hs; }

}  // namespace net
}  // namespace hotplace
