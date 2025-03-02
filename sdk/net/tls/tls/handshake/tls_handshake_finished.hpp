/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_FINISHED__
#define __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_FINISHED__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 5246 7.4.9.  Finished
 */
class tls_handshake_finished : public tls_handshake {
   public:
    tls_handshake_finished(tls_session* session);

    virtual void run_scheduled(tls_direction_t dir);

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
