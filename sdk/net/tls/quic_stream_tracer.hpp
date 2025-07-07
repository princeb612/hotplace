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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSTREAMTRACER__
#define __HOTPLACE_SDK_NET_TLS_QUICSTREAMTRACER__

#include <queue>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_stream_tracer {
    friend class tls_session;

   public:
    quic_stream_tracer();
    ~quic_stream_tracer();

    // session level sketch
    //   violation check
    //     stream_id *-initiated *-direction
    //   reassemble here ?
    //     QUIC STREAM  - stream_id, Fin, Len, Off
    //     HTTP/3 FRAME - type, len(reassemble size)

   protected:
   private:
};

}  // namespace net
}  // namespace hotplace

#endif
