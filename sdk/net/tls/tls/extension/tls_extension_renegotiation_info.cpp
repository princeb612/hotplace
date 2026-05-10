/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_renegotiation_info.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc RFC 5746
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_renegotiation_info_length[] = "renegotiation_info len";
constexpr char constexpr_renegotiation_info[] = "renegotiation_info";

tls_extension_renegotiation_info::tls_extension_renegotiation_info(tls_handshake* handshake) : tls_extension(tls_ext_renegotiation_info, handshake) {}

tls_extension_renegotiation_info::~tls_extension_renegotiation_info() {}

return_t tls_extension_renegotiation_info::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream) && (pos < size); })
        .run_trycatch([&]() -> return_t {
            return_t rc = success;
            auto session = get_handshake()->get_session();
            auto& protection = session->get_tls_protection();
            auto& secrets = protection.get_secrets();

            payload pl;
            pl << new payload_member(uint8(0), constexpr_renegotiation_info_length)  //
               << new payload_member(binary_t(), constexpr_renegotiation_info);
            pl.set_reference_value(constexpr_renegotiation_info, constexpr_renegotiation_info_length);

            rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

#if defined DEBUG
            uint8 len = 0;
            len = pl.t_value_of<uint8>(constexpr_renegotiation_info_length);
#endif
            binary_t info;
            pl.get_binary(constexpr_renegotiation_info, info);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    dbs.println("   > %s %u", constexpr_renegotiation_info_length, len);
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(info, &dbs, 16, 4, 0x0, dump_notrunc);
                    }
                });
            }
#endif

            auto flow = protection.get_flow();
            if (tls_flow_renegotiation == flow) {
                // client renegotiation
                if (info.empty()) {
                    rc = errorcode_t::illegal_parameter;
                } else {
                    const auto& client_verifydata = secrets.get(tls_context_client_verifydata);
                    if (from_client == dir) {
                        if (client_verifydata != info) {
                            rc = errorcode_t::illegal_parameter;
                        }
                    } else if (from_server == dir) {
                        const auto& server_verifydata = secrets.get(tls_context_server_verifydata);
                        binary_t verifydata;
                        binary_append(verifydata, client_verifydata);
                        binary_append(verifydata, server_verifydata);
                        if (verifydata != info) {
                            rc = errorcode_t::illegal_parameter;
                        }
                    }
                }
            } else {
                // client renegotiation prohibited
                if (info.empty()) {
                    // do nothing
                } else {
                    rc = errorcode_t::illegal_parameter;
                }
            }
            if (errorcode_t::success != rc) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_illegal_parameter);
                session->reset_session_status();
                return rc;
            }

            return success;
        });
    return pipeline.result();
}

return_t tls_extension_renegotiation_info::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            binary_t renegotiation_info;

            auto session = get_handshake()->get_session();
            auto& protection = session->get_tls_protection();
            auto& secrets = protection.get_secrets();
            auto flow = protection.get_flow();
            if (tls_flow_renegotiation == flow) {
                // 0 != session_conf_enable_renegotiation
                const auto& client_verifydata = secrets.get(tls_context_client_verifydata);
                if (from_client == dir) {
                    binary_append(renegotiation_info, client_verifydata);
                } else if (from_server == dir) {
                    const auto& server_verifydata = secrets.get(tls_context_server_verifydata);
                    binary_append(renegotiation_info, client_verifydata);
                    binary_append(renegotiation_info, server_verifydata);
                }
            }

            payload pl;
            pl << new payload_member(uint8(renegotiation_info.size()), constexpr_renegotiation_info_length)  //
               << new payload_member(renegotiation_info, constexpr_renegotiation_info);

            return pl.write(bin);
        });
    return pipeline.result();
}

}  // namespace net
}  // namespace hotplace
