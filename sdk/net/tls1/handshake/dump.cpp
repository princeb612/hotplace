/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension
 * Definitions RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/handshake/tls_handshake.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_handshake(tls_session *session, const byte_t *stream, size_t size, size_t &pos, stream_t *debugstream, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        {
            if (size - pos < 4) {
                ret = errorcode_t::no_more;
                __leave2;
            }

            tls_hs_type_t hs = (tls_hs_type_t)stream[pos];
            tls_handshake_builder builder;
            auto handshake = builder.set(hs).set(session).build();
            if (handshake) {
                ret = handshake->read(dir, stream, size, pos, debugstream);
                handshake->release();
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
