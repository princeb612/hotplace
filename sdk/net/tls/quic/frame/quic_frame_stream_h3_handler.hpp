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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMESTREAMH3HANDLER__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMESTREAMH3HANDLER__

#include <sdk/net/tls/quic/frame/quic_frame_stream_handler.hpp>

namespace hotplace {
namespace net {

class quic_frame_stream_h3_handler : public quic_frame_stream_handler {
   public:
    quic_frame_stream_h3_handler(tls_session* session);
    virtual ~quic_frame_stream_h3_handler();

    virtual return_t read(uint64 streamid);
};

}  // namespace net
}  // namespace hotplace

#endif
