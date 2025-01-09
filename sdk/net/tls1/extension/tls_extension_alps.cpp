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
#include <sdk/net/tls1/extension/tls_extension_alps.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_alps_len[] = "alps len";
constexpr char constexpr_alpn_len[] = "alpn len";
constexpr char constexpr_alpn[] = "alpn";

tls_extension_alps::tls_extension_alps(tls_session* session) : tls_extension(tls1_ext_application_layer_protocol_settings, session), _alps_len(0) {}

return_t tls_extension_alps::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 alps_len = 0;
        uint8 alpn_len = 0;
        binary_t alpn;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_alps_len) << new payload_member(binary_t(), constexpr_alpn);
            pl.set_reference_value(constexpr_alpn, constexpr_alps_len);
            pl.read(stream, endpos_extension(), pos);

            alps_len = pl.t_value_of<uint16>(constexpr_alps_len);
            pl.get_binary(constexpr_alpn, alpn);
        }

        if (debugstream) {
            debugstream->printf(" > %s %i\n", constexpr_alps_len, alps_len);
            dump_memory(alpn, debugstream, 16, 3, 0x0, dump_notrunc);
        }

        {
            _alps_len = alps_len;
            _alpn = std::move(alpn);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_alps::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

const binary_t& tls_extension_alps::get_alpn() { return _alpn; }

}  // namespace net
}  // namespace hotplace
