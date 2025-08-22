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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMESTREAMHANDLER__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMESTREAMHANDLER__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/http/http3/types.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_frame_stream_handler {
   public:
    virtual ~quic_frame_stream_handler();

    virtual return_t read(uint64 stream_id);

    void addref();
    void release();

    tls_session* get_session();

   protected:
    quic_frame_stream_handler(tls_session* session);

   private:
    tls_session* _session;

    t_shared_reference<quic_frame_stream_handler> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
