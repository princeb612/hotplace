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

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_extension.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_entry_len[] = "entry len";
constexpr char constexpr_name_type[] = "name type";
constexpr char constexpr_hostname_len[] = "hostname len";
constexpr char constexpr_hostname[] = "hostname";

tls_extension_sni::tls_extension_sni(tls_session* session) : tls_extension(tls1_ext_server_name, session), _nametype(0) {}

return_t tls_extension_sni::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 6066 3.  Server Name Indication

        uint16 first_entry_len = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_entry_len);
            pl.read(stream, endpos_extension(), pos);
        }

        uint8 type = 0;
        uint16 hostname_len = 0;
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
            pl << new payload_member(uint8(0), constexpr_name_type) << new payload_member(uint16(0), true, constexpr_hostname_len)
               << new payload_member(binary_t(), constexpr_hostname);
            pl.set_reference_value(constexpr_hostname, constexpr_hostname_len);
            pl.read(stream, endpos_extension(), pos);

            type = pl.t_value_of<uint8>(constexpr_name_type);
            hostname_len = pl.t_value_of<uint16>(constexpr_hostname_len);
            pl.get_binary(constexpr_hostname, hostname);
        }

        {
            _nametype = type;
            _hostname = std::move(hostname);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_sni::write(binary_t& bin) { return not_supported; }

return_t tls_extension_sni::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_extension::dump(stream, size, s);

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto type = get_nametype();
            const binary_t& hostname = get_hostname();

            s->printf(" > %s %i (%s)\n", constexpr_name_type, type, tlsadvisor->sni_nametype_string(type).c_str());  // 00 host_name
            s->printf(" > %s %s\n", constexpr_hostname, bin2str(hostname).c_str());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

uint8 tls_extension_sni::get_nametype() { return _nametype; }

void tls_extension_sni::set_hostname(const std::string& hostname) {
    _hostname.clear();
    _hostname << hostname;
}

const binary_t& tls_extension_sni::get_hostname() { return _hostname; }

}  // namespace net
}  // namespace hotplace
