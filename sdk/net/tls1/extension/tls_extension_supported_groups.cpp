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

constexpr char constexpr_curves[] = "curves";
constexpr char constexpr_curve[] = "curve";

tls_extension_supported_groups::tls_extension_supported_groups(tls_session* session) : tls_extension(tls1_ext_supported_groups, session) {}

return_t tls_extension_supported_groups::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
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
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i\n", constexpr_curves, curves);
            for (auto i = 0; i < curves; i++) {
                auto curve = t_binary_to_integer<uint16>(&supported_groups[i << 1], sizeof(uint16));
                debugstream->printf("   [%i] 0x%04x(%i) %s\n", i, curve, curve, tlsadvisor->supported_group_string(curve).c_str());
            }
        }

        {
            //
            _supported_groups = std::move(supported_groups);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_supported_groups::write(binary_t& bin, stream_t* debugstream) { return not_supported; }

tls_extension_supported_groups& tls_extension_supported_groups::add_group(uint16 group) {
    binary_append(_supported_groups, group, hton16);
    return *this;
}

const binary_t& tls_extension_supported_groups::get_supported_groups() { return _supported_groups; }

}  // namespace net
}  // namespace hotplace
