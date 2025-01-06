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

return_t tls_extension_client_supported_versions::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // uint16 count = 0;
        binary_t versions;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_versions) << new payload_member(binary_t(), constexpr_version);
            pl.set_reference_value(constexpr_version, constexpr_versions);
            pl.read(stream, endpos_extension(), pos);

            // count = pl.t_value_of<uint8>(constexpr_versions) >> 1;
            pl.get_binary(constexpr_version, versions);
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

return_t tls_extension_client_supported_versions::write(binary_t& bin) { return errorcode_t::not_supported; }

return_t tls_extension_client_supported_versions::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::dump(stream, size, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            const binary_t& versions = _versions;
            uint8 count = versions.size() >> 1;

            s->printf(" > %s %i\n", constexpr_versions, count);
            for (auto i = 0; i < count; i++) {
                auto ver = t_binary_to_integer<uint16>(&versions[i << 1], sizeof(uint16));
                s->printf("   [%i] 0x%04x %s\n", i, ver, tlsadvisor->tls_version_string(ver).c_str());
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

tls_extension_server_supported_versions::tls_extension_server_supported_versions(tls_session* session)
    : tls_extension_supported_versions(session), _version(0) {}

return_t tls_extension_server_supported_versions::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        ret = tls_extension::read(stream, size, pos);
        if (errorcode_t::success != ret) {
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

return_t tls_extension_server_supported_versions::write(binary_t& bin) { return errorcode_t::not_supported; }

return_t tls_extension_server_supported_versions::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::dump(stream, size, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            uint16 version = get_version();

            s->printf(" > 0x%04x %s\n", version, tlsadvisor->tls_version_string(version).c_str());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

uint16 tls_extension_server_supported_versions::get_version() { return _version; }

}  // namespace net
}  // namespace hotplace
