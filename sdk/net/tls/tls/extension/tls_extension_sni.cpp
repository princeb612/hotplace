/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_sni.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_entry_len[] = "entry len";
constexpr char constexpr_name_type[] = "name type";
constexpr char constexpr_hostname_len[] = "hostname len";
constexpr char constexpr_hostname[] = "hostname";

tls_extension_sni::tls_extension_sni(tls_handshake* handshake) : tls_extension(tls_extension_type_t::server_name, handshake), _nametype(0) {}

tls_extension_sni::~tls_extension_sni() {}

return_t tls_extension_sni::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 6066 3.  Server Name Indication
        auto handshake = get_handshake();
        const bool server_acknowledges_sni = (from_server == dir) && (nullptr != handshake) && (tls_handshake_type_t::encrypted_extensions == handshake->get_type());

        // uint16 first_entry_len = 0;
        uint8 type = 0;
        // uint16 hostname_len = 0;
        binary_t hostname;
        {
            /**
             *  struct {
             *      NameType name_type;
             *      select (name_type) {
             *          case host_name: HostName;
             *      } name;
             *  } ServerName;
             *  enum {
             *      host_name(0), (255)
             *  } NameType;
             *  opaque HostName<1..2^16-1>;
             *  struct {
             *      ServerName server_name_list<1..2^16-1>
             *  } ServerNameList;
             */
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_entry_len)     //
               << new payload_member(uint8(0), constexpr_name_type)            //
               << new payload_member(uint16(0), true, constexpr_hostname_len)  //
               << new payload_member(binary_t(), constexpr_hostname);
            pl.set_reference_value(constexpr_hostname, constexpr_hostname_len);
            ret = pl.read(stream, endpos_extension(), pos);
            if (server_acknowledges_sni) {
                if (errorcode_t::no_data == ret) {
                    // RFC 8446 4.2.2: the server acknowledges SNI with an empty
                    // extension_data field; payload::read reports no_data for it.
                    _nametype = 0;
                    _hostname.clear();
                    ret = errorcode_t::success;
                    __leave2;
                }
                // A server_name acknowledgment in EncryptedExtensions must be empty.
                auto session = handshake->get_session();
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
            if (errorcode_t::success != ret) {
                auto session = handshake->get_session();
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            type = pl.t_value_of<uint8>(constexpr_name_type);
            // hostname_len = pl.t_value_of<uint16>(constexpr_hostname_len);
            pl.get_binary(constexpr_hostname, hostname);
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();

                dbs.println("   > %s %i (%s)", constexpr_name_type, type, tlsadvisor->nameof_sni_nametype(type).c_str());  // 00 host_name
                dbs.println("   > %s %s", constexpr_hostname, to_string(hostname).c_str());
            });
        }
#endif

        {
            _nametype = type;
            _hostname = std::move(hostname);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_sni::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    {
        uint8 type = get_nametype();
        const binary_t& hostname = get_hostname();
        uint16 entry_len = t_narrow_cast(1 + hostname.size());

        payload pl;
        pl << new payload_member(uint16(entry_len), true, constexpr_entry_len)           //
           << new payload_member(uint8(type), constexpr_name_type)                       //
           << new payload_member(uint16(hostname.size()), true, constexpr_hostname_len)  //
           << new payload_member(hostname, constexpr_hostname);
        pl.write(bin);
    }

    return ret;
}

uint8 tls_extension_sni::get_nametype() const { return _nametype; }

binary_t& tls_extension_sni::get_hostname() { return _hostname; }

void tls_extension_sni::set_hostname(const std::string server) { _hostname.assign(server.begin(), server.end()); }

}  // namespace net
}  // namespace hotplace
