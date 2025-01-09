/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/extension/tls_extension_alpn.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_alpn_len[] = "alpn len";
constexpr char constexpr_protocol[] = "alpn protocol";

tls_extension_alpn::tls_extension_alpn(tls_session* session) : tls_extension(tls1_ext_application_layer_protocol_negotiation, session) {}

return_t tls_extension_alpn::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 alpn_len = 0;
        binary_t protocols;
        {
            // RFC 7301

            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_alpn_len) << new payload_member(binary_t(0), constexpr_protocol);
            pl.set_reference_value(constexpr_protocol, constexpr_alpn_len);
            pl.read(stream, endpos_extension(), pos);

            alpn_len = pl.t_value_of<uint16>(constexpr_alpn_len);
            pl.get_binary(constexpr_protocol, protocols);
        }

        if (debugstream) {
            debugstream->printf(" > %s %i\n", constexpr_alpn_len, alpn_len);
            dump_memory(protocols, debugstream, 16, 3, 0x0, dump_notrunc);
        }

        {
            //
            _protocols = std::move(protocols);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_alpn::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

const binary_t& tls_extension_alpn::get_protocols() { return _protocols; }

}  // namespace net
}  // namespace hotplace
