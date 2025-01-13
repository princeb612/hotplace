/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_versions[] = "supported versions";
constexpr char constexpr_version[] = "version";

tls_extension_supported_versions::tls_extension_supported_versions(tls_session* session) : tls_extension(tls1_ext_supported_versions, session) {}

tls_extension_client_supported_versions::tls_extension_client_supported_versions(tls_session* session) : tls_extension_supported_versions(session) {}

return_t tls_extension_client_supported_versions::do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 count = 0;
        binary_t versions;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_versions) << new payload_member(binary_t(), constexpr_version);
            pl.set_reference_value(constexpr_version, constexpr_versions);
            pl.read(stream, endpos_extension(), pos);

            count = pl.t_value_of<uint8>(constexpr_versions) >> 1;
            pl.get_binary(constexpr_version, versions);

            for (auto i = 0; i < count; i++) {
                auto ver = t_binary_to_integer<uint16>(&versions[i << 1], sizeof(uint16));
                add(ver);
            }
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i\n", constexpr_versions, count);
            int i = 0;
            for (auto ver : _versions) {
                debugstream->printf("   [%i] 0x%04x %s\n", i++, ver, tlsadvisor->tls_version_string(ver).c_str());
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_client_supported_versions::do_write_body(binary_t& bin, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    uint8 cbsize_versions = 0;
    binary_t bin_versions;
    {
        for (auto ver : _versions) {
            binary_append(bin_versions, ver, hton16);
        }
        cbsize_versions = bin_versions.size();
    }
    {
        payload pl;
        pl << new payload_member(cbsize_versions, constexpr_versions) << new payload_member(bin_versions, constexpr_version);
        pl.write(bin);
    }
    return ret;
}

tls_extension_client_supported_versions& tls_extension_client_supported_versions::add(uint16 code) {
    _versions.push_back(code);
    return *this;
}

tls_extension_server_supported_versions::tls_extension_server_supported_versions(tls_session* session)
    : tls_extension_supported_versions(session), _version(0) {}

return_t tls_extension_server_supported_versions::do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        uint16 version = 0;

        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_version);
            pl.read(stream, endpos_extension(), pos);

            version = pl.t_value_of<uint16>(constexpr_version);
        }

        {
            auto& protection = session->get_tls_protection();
            protection.set_tls_version(version);
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > 0x%04x %s\n", version, tlsadvisor->tls_version_string(version).c_str());
        }

        {
            //
            _version = version;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_server_supported_versions::do_write_body(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

uint16 tls_extension_server_supported_versions::get_version() { return _version; }

}  // namespace net
}  // namespace hotplace
