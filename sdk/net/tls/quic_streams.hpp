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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSTREAMS__
#define __HOTPLACE_SDK_NET_TLS_QUICSTREAMS__

#include <queue>
#include <sdk/base/basic/binaries.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * reassemble
 * see RFC 9000 19.8.  STREAM Frames
 */
class quic_streams {
    friend class tls_session;

   public:
    quic_streams();
    ~quic_streams();

    quic_streams& add(quic_frame_stream* stream);
    quic_streams& operator<<(quic_frame_stream* stream);

   protected:
    return_t consume(quic_frame_stream* stream);

    void clear();
    void clear(uint64 streamid);

   private:
    t_fragmented_binaries<uint64, quic_frame_stream> _streams;
    std::map<uint64, uint64> _encoders;
    qpack_dynamic_table _qpack_dyntable;
};

}  // namespace net
}  // namespace hotplace

#endif
