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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSESSION__
#define __HOTPLACE_SDK_NET_TLS_QUICSESSION__

#include <queue>
#include <sdk/base/basic/binaries.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_session {
   public:
    quic_session();
    ~quic_session();

    // settings, headers
    qpack_dynamic_table& get_dynamic_table();
    // ack
    t_ovl_points<uint32>& get_pkns(protection_space_t space);
    // stream
    quic_session& add(quic_frame_stream* stream);
    quic_session& operator<<(quic_frame_stream* stream);

   protected:
    return_t consume(quic_frame_stream* stream);

    void clear();
    void clear(uint64 streamid);

   private:
    // settings, headers
    qpack_dynamic_table _qpack_dyntable;
    // ack
    std::map<protection_space_t, t_ovl_points<uint32>> _pkn;
    // stream
    t_fragmented_binaries<uint64, quic_frame_stream> _streams;
    std::map<uint64, uint64> _encoders;
};

}  // namespace net
}  // namespace hotplace

#endif
