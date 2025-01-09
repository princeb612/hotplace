/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_FINISHED__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_FINISHED__

#include <sdk/net/tls1/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_finished : public tls_handshake {
   public:
    tls_handshake_finished(tls_session* session);

   protected:
    virtual return_t do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
};

}  // namespace net
}  // namespace hotplace

#endif
