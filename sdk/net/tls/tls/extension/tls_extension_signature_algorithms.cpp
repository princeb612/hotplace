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
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_algorithms[] = "algorithms";
constexpr char constexpr_algorithm[] = "algorithm";

tls_extension_signature_algorithms::tls_extension_signature_algorithms(tls_session* session) : tls_extension(tls1_ext_signature_algorithms, session) {}

return_t tls_extension_signature_algorithms::do_postprocess() {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& protection_context = protection.get_protection_context();
    protection_context.clear_signature_algorithms();
    for (auto alg : _algorithms) {
        protection_context.add_signature_algorithm(alg);
    }
    return ret;
}

return_t tls_extension_signature_algorithms::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        // RFC 8446 4.2.3.  Signature Algorithms

        binary_t algorithms;
        uint16 count = 0;

        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_algorithms) << new payload_member(binary_t(), constexpr_algorithm);
            pl.set_reference_value(constexpr_algorithm, constexpr_algorithms);
            pl.read(stream, endpos_extension(), pos);

            count = pl.t_value_of<uint16>(constexpr_algorithms) >> 1;
            pl.get_binary(constexpr_algorithm, algorithms);

            for (auto i = 0; i < count; i++) {
                auto alg = t_binary_to_integer<uint16>(&algorithms[i << 1], sizeof(uint16));
                add(alg);
            }
        }

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            dbs.println("   > %s %i", constexpr_algorithms, count);
            int i = 0;
            for (auto alg : _algorithms) {
                dbs.println("     [%i] 0x%04x %s", i++, alg, tlsadvisor->signature_scheme_name(alg).c_str());
            }

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_signature_algorithms::do_write_body(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        uint16 cbsize_algorithms = 0;
        binary_t bin_algorithms;
        {
            for (auto alg : _algorithms) {
                binary_append(bin_algorithms, alg, hton16);
            }
            cbsize_algorithms = bin_algorithms.size();
        }
        {
            payload pl;
            pl << new payload_member(cbsize_algorithms, true, constexpr_algorithms) << new payload_member(bin_algorithms, constexpr_algorithm);
            pl.write(bin);
        }
    }
    __finally2 {}
    return ret;
}

tls_extension_signature_algorithms& tls_extension_signature_algorithms::add(uint16 code) {
    _algorithms.push_back(code);
    return *this;
}

tls_extension_signature_algorithms& tls_extension_signature_algorithms::add(const std::string& name) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto code = tlsadvisor->signature_scheme_code(name);
    return add(code);
}

void tls_extension_signature_algorithms::clear() { _algorithms.clear(); }

}  // namespace net
}  // namespace hotplace
