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
#include <sdk/net/tls1/extension/tls_extension_compress_certificate.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_algorithm_len[] = "algorithm len";
constexpr char constexpr_algorithm[] = "algorithm";

tls_extension_compress_certificate::tls_extension_compress_certificate(tls_session* session) : tls_extension(tls1_ext_compress_certificate, session) {}

return_t tls_extension_compress_certificate::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint8 algorithm_len = 0;
        binary_t algorithms;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_algorithm_len) << new payload_member(binary_t(), constexpr_algorithm);
            pl.set_reference_value(constexpr_algorithm, constexpr_algorithm_len);
            pl.read(stream, endpos_extension(), pos);

            algorithm_len = pl.t_value_of<uint8>(constexpr_algorithm_len);
            pl.get_binary(constexpr_algorithm, algorithms);
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i (%i)\n", constexpr_algorithm_len, algorithm_len, algorithm_len >> 1);
            for (auto i = 0; i < algorithm_len / sizeof(uint16); i++) {
                auto alg = t_binary_to_integer<uint16>(&algorithms[i << 1], sizeof(uint16));
                debugstream->printf("   [%i] 0x%04x %s\n", i, alg, tlsadvisor->cert_compression_algid_string(alg).c_str());
            }
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

return_t tls_extension_compress_certificate::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

tls_extension_compress_certificate& tls_extension_compress_certificate::add_algorithm(uint16 alg) {
    binary_append(_algorithms, alg, hton16);
    return *this;
}

const binary_t& tls_extension_compress_certificate::get_algorithms() { return _algorithms; }

}  // namespace net
}  // namespace hotplace
