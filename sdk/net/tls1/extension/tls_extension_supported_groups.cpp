/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_curves[] = "curves";
constexpr char constexpr_curve[] = "curve";

tls_extension_supported_groups::tls_extension_supported_groups(tls_session* session) : tls_extension(tls1_ext_supported_groups, session) {}

return_t tls_extension_supported_groups::do_postprocess() {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& protection_context = protection.get_protection_context();

    protection_context.clear_supported_groups();
    for (auto curve : _supported_groups) {
        protection_context.add_supported_group(curve);
    }
    return ret;
}

return_t tls_extension_supported_groups::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        binary_t supported_groups;
        uint16 curves = 0;

        {
            // RFC 8422 5.  Data Structures and Computations
            //  struct {
            //      NamedCurve named_curve_list<2..2^16-1>
            //  } NamedCurveList;

            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_curves) << new payload_member(binary_t(0), constexpr_curve);
            pl.set_reference_value(constexpr_curve, constexpr_curves);
            pl.read(stream, endpos_extension(), pos);

            curves = pl.t_value_of<uint16>(constexpr_curves) >> 1;
            pl.get_binary(constexpr_curve, supported_groups);

            for (auto i = 0; i < curves; i++) {
                auto curve = t_binary_to_integer<uint16>(&supported_groups[i << 1], sizeof(uint16));
                add(curve);
            }
        }

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            dbs.printf(" > %s %i\n", constexpr_curves, curves);
            int i = 0;
            for (auto curve : _supported_groups) {
                dbs.printf("   [%i] 0x%04x(%i) %s\n", i++, curve, curve, tlsadvisor->supported_group_name(curve).c_str());
            }

            trace_debug_event(category_tls1, tls_event_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_supported_groups::do_write_body(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        uint16 cbsize_supported_groups = 0;
        binary_t bin_supported_groups;
        {
            for (auto curve : _supported_groups) {
                binary_append(bin_supported_groups, curve, hton16);
            }
            cbsize_supported_groups = bin_supported_groups.size();
        }
        {
            payload pl;
            pl << new payload_member(uint16(cbsize_supported_groups), true, constexpr_curves) << new payload_member(bin_supported_groups, constexpr_curve);
            pl.write(bin);
        }
    }
    __finally2 {}
    return ret;
}

tls_extension_supported_groups& tls_extension_supported_groups::add(uint16 code) {
    if (code) {
        _supported_groups.push_back(code);
    }
    return *this;
}

tls_extension_supported_groups& tls_extension_supported_groups::add(const std::string& name) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    uint16 code = tlsadvisor->supported_group_code(name);
    return add(code);
}

void tls_extension_supported_groups::clear() { _supported_groups.clear(); }

}  // namespace net
}  // namespace hotplace
