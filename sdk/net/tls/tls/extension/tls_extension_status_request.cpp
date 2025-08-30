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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_status_request.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_cert_status_type[] = "certificate status type";
constexpr char constexpr_responderid_info_len[] = "responderid information len";
constexpr char constexpr_responderid_info[] = "responderid information";
constexpr char constexpr_request_ext_info_len[] = "request extension information len";
constexpr char constexpr_request_ext_info[] = "request extension information";

tls_extension_status_request::tls_extension_status_request(tls_handshake* handshake) : tls_extension(tls_ext_status_request, handshake) {}

tls_extension_status_request::~tls_extension_status_request() {}

return_t tls_extension_status_request::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint8 cert_status_type = 0;
        uint16 responderid_info_len = 0;
        uint16 request_ext_info_len = 0;
        binary_t responderid_info;
        binary_t request_ext_info;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_cert_status_type)             //
               << new payload_member(uint16(), true, constexpr_responderid_info_len)   //
               << new payload_member(binary_t(), constexpr_responderid_info)           //
               << new payload_member(uint16(0), true, constexpr_request_ext_info_len)  //
               << new payload_member(binary_t(), constexpr_request_ext_info);
            pl.set_reference_value(constexpr_responderid_info, constexpr_responderid_info_len);
            pl.set_reference_value(constexpr_request_ext_info, constexpr_request_ext_info_len);
            pl.read(stream, endpos_extension(), pos);

            cert_status_type = pl.t_value_of<uint8>(constexpr_cert_status_type);
            responderid_info_len = pl.t_value_of<uint8>(constexpr_responderid_info_len);
            request_ext_info_len = pl.t_value_of<uint8>(constexpr_request_ext_info_len);
            pl.get_binary(constexpr_responderid_info, responderid_info);
            pl.get_binary(constexpr_request_ext_info, request_ext_info);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            dbs.println("   > %s %i %s", constexpr_cert_status_type, cert_status_type, tlsadvisor->cert_status_type_string(cert_status_type).c_str());
            dbs.println("   > %s %i", constexpr_responderid_info_len, responderid_info_len);
            if (check_trace_level(loglevel_debug)) {
                dump_memory(responderid_info, &dbs, 16, 4, 0x0, dump_notrunc);
            }
            dbs.println("   > %s %i", constexpr_request_ext_info_len, request_ext_info_len);
            if (check_trace_level(loglevel_debug)) {
                dump_memory(request_ext_info, &dbs, 16, 4, 0x0, dump_notrunc);
            }

            trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
        }
#endif

        {
            _cert_status_type = cert_status_type;
            _responderid_info = std::move(responderid_info);
            _request_ext_info = std::move(request_ext_info);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_status_request::do_write_body(tls_direction_t dir, binary_t& bin) { return not_supported; }

uint8 tls_extension_status_request::get_cert_status_type() { return _cert_status_type; }

void tls_extension_status_request::set_responderid_info(const binary_t& info) { _responderid_info = info; }

const binary_t& tls_extension_status_request::get_responderid_info() { return _responderid_info; }

void tls_extension_status_request::set_request_ext_info(const binary_t& info) { _request_ext_info = info; }

const binary_t& tls_extension_status_request::get_request_ext_info() { return _request_ext_info; }

}  // namespace net
}  // namespace hotplace
