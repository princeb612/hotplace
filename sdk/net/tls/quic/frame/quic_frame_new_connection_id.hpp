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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMENEWCONNECTIONID__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMENEWCONNECTIONID__

#include <hotplace/sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.9.  MAX_DATA Frames
// RFC 9000 19.10. MAX_STREAM_DATA Frames
// RFC 9000 19.11. MAX_STREAMS Frames
// RFC 9000 19.12. DATA_BLOCKED Frames
// RFC 9000 19.13. STREAM_DATA_BLOCKED Frames
// RFC 9000 19.14. STREAMS_BLOCKED Frames
// RFC 9000 19.15. NEW_CONNECTION_ID Frames
class quic_frame_new_connection_id : public quic_frame {
   public:
    quic_frame_new_connection_id(tls_session* session);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
