/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMECRYPTO__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMECRYPTO__

#include <hotplace/sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.6.  CRYPTO Frames
class quic_frame_crypto : public quic_frame {
   public:
    quic_frame_crypto(tls_session* session);
    virtual ~quic_frame_crypto();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual return_t do_write_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, size_t len, binary_t& bin);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
