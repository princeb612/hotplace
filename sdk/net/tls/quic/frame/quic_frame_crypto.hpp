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

#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.6.  CRYPTO Frames
class quic_frame_crypto : public quic_frame {
   public:
    quic_frame_crypto(quic_packet* packet);

    /**
     * CRYPTO
     *     Frame Type: CRYPTO (0x0000000000000006)
     *     Offset: 4645
     *     Length: 682
     *     Crypto Data
     *     TLSv1.3 Record Layer: Handshake Protocol: Multiple Handshake Messages
     *         Handshake Protocol: Certificate (last fragment)
     *         Handshake Protocol: Certificate
     *         Handshake Protocol: Certificate Verify
     *         Handshake Protocol: Finished
     */
    quic_frame_crypto& operator<<(tls_handshake* handshake);

    tls_handshakes& get_handshakes();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

    tls_handshakes _handshakes;
};

}  // namespace net
}  // namespace hotplace

#endif
