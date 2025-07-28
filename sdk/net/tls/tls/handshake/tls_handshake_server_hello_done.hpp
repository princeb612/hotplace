/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKESERVERHELLODONE__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKESERVERHELLODONE__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_server_hello_done : public tls_handshake {
   public:
    tls_handshake_server_hello_done(tls_session* session);
    virtual ~tls_handshake_server_hello_done();

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
