/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKEUNKNOWN__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKEUNKNOWN__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_unknown : public tls_handshake {
   public:
    tls_handshake_unknown(tls_hs_type_t type, tls_session* session);
    virtual ~tls_handshake_unknown();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
