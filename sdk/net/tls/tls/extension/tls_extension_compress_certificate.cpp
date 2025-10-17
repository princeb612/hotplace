/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_compress_certificate.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_algorithm_len[] = "algorithm len";
constexpr char constexpr_algorithm[] = "algorithm";

tls_extension_compress_certificate::tls_extension_compress_certificate(tls_handshake* handshake) : tls_extension(tls_ext_compress_certificate, handshake) {}

tls_extension_compress_certificate::~tls_extension_compress_certificate() {}

return_t tls_extension_compress_certificate::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint8 algorithms_len = 0;
        binary_t bin_algorithms;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_algorithm_len)  //
               << new payload_member(binary_t(), constexpr_algorithm);
            pl.set_reference_value(constexpr_algorithm, constexpr_algorithm_len);
            pl.read(stream, endpos_extension(), pos);

            algorithms_len = pl.t_value_of<uint8>(constexpr_algorithm_len) >> 1;
            pl.get_binary(constexpr_algorithm, bin_algorithms);

            for (auto i = 0; i < algorithms_len; i++) {
                auto alg = t_binary_to_integer<uint16>(&bin_algorithms[i << 1], sizeof(uint16));
                add(alg);
            }
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();

                dbs.println("   > %s %i (%i ent.)", constexpr_algorithm_len, algorithms_len << 1, algorithms_len);
                int i = 0;
                for (auto alg : _algorithms) {
                    dbs.println("     [%i] 0x%04x %s", i++, alg, tlsadvisor->compression_alg_name(alg).c_str());
                }
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_compress_certificate::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    uint8 cbsize_algorithms = 0;
    binary_t bin_algorithms;
    {
        for (auto alg : _algorithms) {
            binary_append(bin_algorithms, alg, hton16);
        }
        cbsize_algorithms = bin_algorithms.size();
    }
    {
        payload pl;
        pl << new payload_member(uint8(cbsize_algorithms), constexpr_algorithm_len)  //
           << new payload_member(bin_algorithms, constexpr_algorithm);
        pl.write(bin);
    }
    return ret;
}

tls_extension_compress_certificate& tls_extension_compress_certificate::add(uint16 code) {
    if (_algorithms.size() < 0xfe) {
        _algorithms.push_back(code);
    }
    return *this;
}

tls_extension_compress_certificate& tls_extension_compress_certificate::add(const std::string& name) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    return *this;
}

void tls_extension_compress_certificate::clear() { _algorithms.clear(); }

}  // namespace net
}  // namespace hotplace
