/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_supported_groups.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_curves[] = "curves";
constexpr char constexpr_curve[] = "curve";

tls_extension_supported_groups::tls_extension_supported_groups(tls_handshake* handshake) : tls_extension(tls_ext_supported_groups, handshake) {}

tls_extension_supported_groups::~tls_extension_supported_groups() {}

return_t tls_extension_supported_groups::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto advisor = crypto_advisor::get_instance();
    auto session = get_handshake()->get_session();
    auto& protection = session->get_tls_protection();
    auto& protection_context = protection.get_protection_context();

    protection_context.clear_supported_groups();
    for (auto curve : _supported_groups) {
        auto hint = advisor->hintof_tls_group(curve);
        if (hint && (tls_flag_support & hint->flags)) {
            protection_context.add_supported_group(curve);
        }
    }
    return ret;
}

return_t tls_extension_supported_groups::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .goahead_if_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream); })
        .run_trycatch([&]() -> return_t {
            binary_t supported_groups;
            uint16 curves = 0;

            {
                // RFC 8422 5.  Data Structures and Computations
                //  struct {
                //      NamedCurve named_curve_list<2..2^16-1>
                //  } NamedCurveList;

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_curves)  //
                   << new payload_member(binary_t(0), constexpr_curve);
                pl.set_reference_value(constexpr_curve, constexpr_curves);

                auto rc = pl.read(stream, endpos_extension(), pos);
                if (false == error_traits<return_t>::is_not_fail(rc)) {
                    __trace_return(rc);
                }

                curves = pl.t_value_of<uint16>(constexpr_curves) >> 1;
                pl.get_binary(constexpr_curve, supported_groups);

                for (auto i = 0; i < curves; i++) {
                    auto curve = t_binary_to_integer<uint16>(&supported_groups[i << 1], sizeof(uint16));
                    add(curve);
                }
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    auto tlsadvisor = tls_advisor::get_instance();

                    dbs.println("   > %s (%i ent.)", constexpr_curves, curves);
                    int i = 0;
                    for (auto curve : _supported_groups) {
                        dbs.println("     [%i] 0x%04x(%i) %s", i++, curve, curve, tlsadvisor->nameof_group(curve).c_str());
                    }
                });
            }
#endif

            return success;
        });
    return pipeline.result();
}

return_t tls_extension_supported_groups::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            auto advisor = crypto_advisor::get_instance();

            uint16 cbsize_supported_groups = 0;
            binary_t bin_supported_groups;
            {
                for (auto curve : _supported_groups) {
                    auto hint = advisor->hintof_tls_group(curve);
                    if (hint && (tls_flag_support & hint->flags)) {
                        binary_append(bin_supported_groups, curve, hton16);
                    }
                }
                cbsize_supported_groups = t_narrow_cast(bin_supported_groups.size());
            }
            {
                payload pl;
                pl << new payload_member(uint16(cbsize_supported_groups), true, constexpr_curves)  //
                   << new payload_member(bin_supported_groups, constexpr_curve);

                return pl.write(bin);
            }
        });
    return pipeline.result();
}

tls_extension_supported_groups& tls_extension_supported_groups::add(uint16 code) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(code);
    if (hint && (tls_flag_support & hint->flags)) {
        _supported_groups.push_back(code);
    }
    return *this;
}

tls_extension_supported_groups& tls_extension_supported_groups::add(const std::string& name) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(name);
    if (hint && (tls_flag_support & hint->flags)) {
        _supported_groups.push_back(hint->group);
    }
    return *this;
}

size_t tls_extension_supported_groups::numberof_groups() { return _supported_groups.size(); }

void tls_extension_supported_groups::clear() { _supported_groups.clear(); }

}  // namespace net
}  // namespace hotplace
