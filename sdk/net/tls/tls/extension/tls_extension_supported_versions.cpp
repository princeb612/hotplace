/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_supported_versions.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_versions[] = "supported versions";
constexpr char constexpr_version[] = "version";

tls_extension_supported_versions::tls_extension_supported_versions(tls_handshake* handshake) : tls_extension(tls_ext_supported_versions, handshake) {}

tls_extension_supported_versions::~tls_extension_supported_versions() {}

tls_extension_client_supported_versions::tls_extension_client_supported_versions(tls_handshake* handshake) : tls_extension_supported_versions(handshake) {}

tls_extension_client_supported_versions::~tls_extension_client_supported_versions() {}

return_t tls_extension_client_supported_versions::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto session = get_handshake()->get_session();
    auto& protection = session->get_tls_protection();
    auto& protection_context = protection.get_protection_context();
    protection_context.clear_supported_versions();
    for (auto ver : _versions) {
        protection_context.add_supported_version(ver);
    }
    return ret;
}

return_t tls_extension_client_supported_versions::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream) && (pos < size); })
        .run_trycatch([&]() -> return_t {
            uint16 count = 0;
            binary_t versions;
            {
                payload pl;
                pl << new payload_member(uint8(0), constexpr_versions)  //
                   << new payload_member(binary_t(), constexpr_version);
                pl.set_reference_value(constexpr_version, constexpr_versions);

                auto rc = pl.read(stream, endpos_extension(), pos);
                if (false == error_traits<return_t>::is_not_fail(rc)) {
                    return rc;
                }

                count = pl.t_value_of<uint8>(constexpr_versions) >> 1;
                pl.get_binary(constexpr_version, versions);

                for (auto i = 0; i < count; i++) {
                    auto ver = t_binary_to_integer<uint16>(&versions[i << 1], sizeof(uint16));
                    add(ver);
                }
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();

                    dbs.println("    > %s (%i ent.)", constexpr_versions, count);
                    int i = 0;
                    for (auto ver : _versions) {
                        dbs.println("      [%i] 0x%04x %s", i++, ver, tlsadvisor->nameof_tls_version(ver).c_str());
                    }
                });
            }
#endif

            return success;
        });
    return pipeline.result();
}

return_t tls_extension_client_supported_versions::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            uint8 cbsize_versions = 0;
            binary_t bin_versions;

            for (auto ver : _versions) {
                binary_append(bin_versions, ver, hton16);
            }
            cbsize_versions = t_narrow_cast(bin_versions.size());

            {
                payload pl;
                pl << new payload_member(cbsize_versions, constexpr_versions)  //
                   << new payload_member(bin_versions, constexpr_version);

                return pl.write(bin);
            }

            return success;
        });
    return pipeline.result();
}

tls_extension_client_supported_versions& tls_extension_client_supported_versions::add(uint16 code) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto hint = tlsadvisor->hintof_tls_version(code);
    if (hint && hint->support) {
        _versions.push_back(code);
    }
    return *this;
}

const std::list<uint16>& tls_extension_client_supported_versions::get_versions() { return _versions; }

tls_extension_server_supported_versions::tls_extension_server_supported_versions(tls_handshake* handshake) : tls_extension_supported_versions(handshake) {}

tls_extension_server_supported_versions::~tls_extension_server_supported_versions() {}

return_t tls_extension_server_supported_versions::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream) && (pos < size); })
        .run_trycatch([&]() -> return_t {
            auto session = get_handshake()->get_session();

            uint16 version = 0;

            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_version);

                auto rc = pl.read(stream, endpos_extension(), pos);
                if (false == error_traits<return_t>::is_not_fail(rc)) {
                    return rc;
                }

                version = pl.t_value_of<uint16>(constexpr_version);
            }

            auto& protection = session->get_tls_protection();
            protection.set_tls_version(version);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();

                    dbs.println("    > 0x%04x %s", version, tlsadvisor->nameof_tls_version(version).c_str());
                });
            }
#endif

            return success;
        });
    return pipeline.result();
}

return_t tls_extension_server_supported_versions::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(uint16(get_version()), true, constexpr_version);

            return pl.write(bin);
        });
    return pipeline.result();
}

uint16 tls_extension_server_supported_versions::get_version() {
    uint16 version = 0;
    auto session = get_handshake()->get_session();
    if (session) {
        auto& protection = session->get_tls_protection();
        version = protection.get_tls_version();
    }
    return version;
}

tls_extension_server_supported_versions& tls_extension_server_supported_versions::set(uint16 code) {
    auto session = get_handshake()->get_session();
    if (session) {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        auto hint = tlsadvisor->hintof_tls_version(code);
        if (hint->support) {
            auto& protection = session->get_tls_protection();
            protection.set_tls_version(code);
        }
    }
    return *this;
}

}  // namespace net
}  // namespace hotplace
