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
#include <sdk/net/tls1/extension/tls_extension_status_request.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_cert_status_type[] = "certificate status type";
constexpr char constexpr_responderid_info_len[] = "responderid information len";
constexpr char constexpr_responderid_info[] = "responderid information";
constexpr char constexpr_request_ext_info_len[] = "request extension information len";
constexpr char constexpr_request_ext_info[] = "request extension information";

tls_extension_status_request::tls_extension_status_request(tls_session* session) : tls_extension(tls1_ext_status_request, session) {}

return_t tls_extension_status_request::do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint8 cert_status_type = 0;
        uint16 responderid_info_len = 0;
        uint16 request_ext_info_len = 0;
        binary_t responderid_info;
        binary_t request_ext_info;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_cert_status_type) << new payload_member(uint16(), true, constexpr_responderid_info_len)
               << new payload_member(binary_t(), constexpr_responderid_info) << new payload_member(uint16(0), true, constexpr_request_ext_info_len)
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

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i %s\n", constexpr_cert_status_type, cert_status_type, tlsadvisor->cert_status_type_string(cert_status_type).c_str());
            debugstream->printf(" > %s %i\n", constexpr_responderid_info_len, responderid_info_len);
            dump_memory(responderid_info, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf(" > %s %i\n", constexpr_request_ext_info_len, request_ext_info_len);
            dump_memory(request_ext_info, debugstream, 16, 3, 0x0, dump_notrunc);
        }

        {
            _cert_status_type = cert_status_type;
            _responderid_info = std::move(responderid_info);
            _request_ext_info = std::move(request_ext_info);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_status_request::write(binary_t& bin, stream_t* debugstream) { return not_supported; }

uint8 tls_extension_status_request::get_cert_status_type() { return _cert_status_type; }

void tls_extension_status_request::set_responderid_info(const binary_t& info) { _responderid_info = info; }

const binary_t& tls_extension_status_request::get_responderid_info() { return _responderid_info; }

void tls_extension_status_request::set_request_ext_info(const binary_t& info) { _request_ext_info = info; }

const binary_t& tls_extension_status_request::get_request_ext_info() { return _request_ext_info; }

}  // namespace net
}  // namespace hotplace
