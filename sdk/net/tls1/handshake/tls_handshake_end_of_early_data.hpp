/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_END_OF_EARLY_DATA__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_END_OF_EARLY_DATA__

#include <sdk/net/tls1/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_end_of_early_data : public tls_handshake {
   public:
    tls_handshake_end_of_early_data(tls_session* session);

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
};

}  // namespace net
}  // namespace hotplace

#endif
