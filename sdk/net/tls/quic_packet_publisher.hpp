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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICPACKETPUBLISHER__
#define __HOTPLACE_SDK_NET_TLS_QUICPACKETPUBLISHER__

#include <queue>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/http/compression/http_header_compression_stream.hpp>
#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_http3_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packets.hpp>
#include <sdk/net/tls/quic/types.hpp>

namespace hotplace {
namespace net {

enum quic_packet_flag_t {
    quic_pad_packet = (1 << 0),
    quic_ack_packet = (1 << 1),
};

/**
 * publisher
 */
class quic_packet_publisher {
   public:
    quic_packet_publisher();
    ~quic_packet_publisher();

    quic_packet_publisher& set_session(tls_session* session);
    quic_packet_publisher& set_payload_size(uint16 size);

    /**
     * @param uint32 flags [in] see quic_packet_flag_t
     */
    quic_packet_publisher& set_flags(uint32 flags);

    tls_session* get_session();
    uint16 get_payload_size();
    uint32 get_flags();

    /**
     * @param   CRYOTO FRAME (initial, handshake, 1-RTT)
     * @param   tls_hs_type_t type [in]
     * @param   tls_direction_t dir [in]
     * @param   std::function<return_t(tls_handshake*, tls_direction_t)> func [in]
     */
    quic_packet_publisher& add(tls_hs_type_t type, tls_direction_t dir, std::function<return_t(tls_handshake*, tls_direction_t)> func);
    /**
     * @param   STREAM FRAME (1-RTT)
     * @param   uint64 stream_id [in]
     * @param   uint8 uni_type [in]
     * @param   h3_frame_t type [in]
     * @param   std::function<return_t(http3_frame*)> func [in]
     */
    quic_packet_publisher& add_stream(uint64 stream_id, uint8 uni_type, h3_frame_t type, std::function<return_t(http3_frame*)> func);
    quic_packet_publisher& add_stream(uint64 stream_id, uint8 uni_type, std::function<return_t(qpack_stream&)> func);
    /**
     * @param   QUIC FRAME (1-RTT)
     * @param   quic_frame_t type [in]
     * @param   std::function<return_t(quic_frame*)> func [in]
     */
    quic_packet_publisher& add(quic_frame_t type, std::function<return_t(quic_frame*)> func);

    return_t publish(tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);

    tls_handshakes& get_handshakes();
    quic_frames& get_frames();

   protected:
    return_t probe_spaces(std::set<protection_space_t>& spaces);
    return_t prepare_frame(protection_space_t space, tls_direction_t dir);
    return_t prepare_packet_cid(quic_packet* packet, protection_space_t space, tls_direction_t dir);
    return_t publish_space(protection_space_t space, tls_direction_t dir, uint32 flags, std::list<binary_t>& container);

    return_t kindof_handshake(tls_handshake* handshake, protection_space_t& space);
    bool is_kindof_handshake(tls_handshake* handshake, protection_space_t space);
    return_t kindof_frame(quic_frame* frame, protection_space_t& space);
    bool is_kindof_frame(quic_frame* frame, protection_space_t space);

   private:
    tls_session* _session;
    uint16 _payload_size;
    uint32 _flags;

    tls_handshakes _handshakes;
    quic_frames _frames;
    std::map<uint32, quic_frame_t> _typemap;
};

}  // namespace net
}  // namespace hotplace

#endif
