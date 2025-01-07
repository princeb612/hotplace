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
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_extension.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_versions[] = "supported versions";
constexpr char constexpr_version[] = "version";

tls_extension_supported_versions::tls_extension_supported_versions(tls_session* session) : tls_extension(tls1_ext_supported_versions, session) {}

tls_extension_client_supported_versions::tls_extension_client_supported_versions(tls_session* session) : tls_extension_supported_versions(session) {}

return_t tls_extension_client_supported_versions::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i\n", constexpr_versions, count);
            for (auto i = 0; i < count; i++) {
                auto ver = t_binary_to_integer<uint16>(&versions[i << 1], sizeof(uint16));
                debugstream->printf("   [%i] 0x%04x %s\n", i, ver, tlsadvisor->tls_version_string(ver).c_str());
            }
        }

        {
            //
            _versions = std::move(versions);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_client_supported_versions::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

tls_extension_server_supported_versions::tls_extension_server_supported_versions(tls_session* session)
    : tls_extension_supported_versions(session), _version(0) {}

return_t tls_extension_server_supported_versions::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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

return_t tls_extension_server_supported_versions::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

uint16 tls_extension_server_supported_versions::get_version() { return _version; }

}  // namespace net
}  // namespace hotplace
