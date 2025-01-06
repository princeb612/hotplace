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

constexpr char constexpr_algorithms[] = "algorithms";
constexpr char constexpr_algorithm[] = "algorithm";

tls_extension_signature_algorithms::tls_extension_signature_algorithms(tls_session* session) : tls_extension(tls1_ext_signature_algorithms, session) {}

return_t tls_extension_signature_algorithms::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 8446 4.2.3.  Signature Algorithms

        binary_t algorithms;

        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_algorithms) << new payload_member(binary_t(), constexpr_algorithm);
            pl.set_reference_value(constexpr_algorithm, constexpr_algorithms);
            pl.read(stream, endpos_extension(), pos);

            // uint16 count = pl.t_value_of<uint16>(constexpr_algorithms) >> 1;
            pl.get_binary(constexpr_algorithm, algorithms);
        }

        {
            //
            _algorithms = std::move(algorithms);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_signature_algorithms::write(binary_t& bin) { return errorcode_t::not_supported; }

return_t tls_extension_signature_algorithms::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::dump(stream, size, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto const& algorithms = get_algorithms();
            uint16 count = algorithms.size() >> 1;

            s->printf(" > %s %i\n", constexpr_algorithms, count);
            for (auto i = 0; i < count; i++) {
                auto alg = t_binary_to_integer<uint16>(&algorithms[i << 1], sizeof(uint16));
                s->printf("   [%i] 0x%04x %s\n", i, alg, tlsadvisor->signature_scheme_string(alg).c_str());
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

tls_extension_signature_algorithms& tls_extension_signature_algorithms::add_algorithm(uint16 alg) {
    binary_append(_algorithms, alg, hton16);
    return *this;
}

const binary_t& tls_extension_signature_algorithms::get_algorithms() { return _algorithms; }

}  // namespace net
}  // namespace hotplace
