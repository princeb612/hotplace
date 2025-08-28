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
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packets.hpp>
#include <sdk/net/tls/quic/types.hpp>

namespace hotplace {
namespace net {

enum quic_packet_flag_t {
    quic_pad_packet = (1 << 0),
    quic_ack_packet = (1 << 1),
};

/**
 * sketch
 *          // case ACK, CRYPTO[CERT, CV, FIN], PADDING
 *          // ex.
 *          //      PKN3 ACK, CRYPTO [CERT.fragment]
 *          //      PKN4 CRYPTO [CERT.fragment]
 *          //      PKN5 CRYPTO [CERT.fragment]
 *          //      PKN6 CRYPTO [CERT.fragment, CV, FIN], PADDING
 *          publisher.set_session(session)
 *                   .set_payload_size(1200)
 *                   .set_flags(quic_pad_packet | quic_ack_packet)
 *                   .add(new tls_handshake_certificate(session))
 *                   .add(new tls_handshake_certificate_verify(session))
 *                   .add(new tls_handshake_finished(session))
 *                   .publish(from_server, [&](tls_session* session, binary_t& packet) -> void { do_something(); });
 *
 *          // case ACK, PADDING
 *          // ex.
 *          //      PKN10 ACK, PADDING
 *          publisher.set_session(session)
 *                   .set_payload_size(1200)
 *                   .set_flags(quic_pad_packet | quic_ack_packet)
 *                   .publish(from_server, [&](tls_session* session, binary_t& packet) -> void { do_something(); });
 *
 *          // case CRYPTO[CERT, CV, FIN], SETTINGS, PADDING
 *          // ex.
 *          //      PKN4 CRYPTO [CERT.fragment]
 *          //      PKN5 CRYPTO [CERT.fragment]
 *          //      PKN6 CRYPTO [CERT.fragment, CV, FIN] + PKN7 SETTINGS, PADDING
 *          publisher.set_session(session)
 *                   .set_payload_size(max_payload_size)
 *                   .set_flags(quic_ack_packet | quic_pad_packet)
 *                   .add(new tls_handshake_certificate(session))
 *                   .add(new tls_handshake_certificate_verify(session))
 *                   .add(new tls_handshake_finished(session))
 *                   .add(settings)
 *                   .set_streaminfo(0x3, h3_control_stream)
 *                   .publish(from_server, [&](tls_session* session, binary_t& packet) -> void { do_something(); });
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
    /**
     * @param uint64 stream_id [in]
     * @param uint8 unitype [in] if bi-directional, ignored
     * @param quic_frame_stream_handler* handler [in]
     */
    quic_packet_publisher& set_streaminfo(uint64 stream_id, uint8 unitype);

    tls_session* get_session();
    uint16 get_payload_size();
    uint32 get_flags();
    uint64 get_streamid();

    /**
     * initial, handshake
     */
    quic_packet_publisher& add(tls_handshake* handshake, bool upref = false);
    /**
     * 1-RTT (constrol stream)
     */
    quic_packet_publisher& add(http3_frame* frame, bool upref = false);

    quic_packet_publisher& operator<<(tls_handshake* handshake);
    quic_packet_publisher& operator<<(http3_frame* frame);

    /**
     * QPACK encoder, decoder stream
     *  publisher.set_session(session).get_qpack_stream().encode_header(":path", "/");
     */
    qpack_stream& get_qpack_stream();

    return_t publish(tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);

   protected:
    return_t probe_spaces(std::set<protection_space_t>& spaces);
    return_t publish_space(protection_space_t space, tls_direction_t dir, uint32 flags, std::list<binary_t>& container);

    bool is_kindof_initial(tls_handshake* handshake);
    bool is_kindof_handshake(tls_handshake* handshake);

    tls_handshakes& get_handshakes();
    http3_frames& get_frames();

   private:
    tls_session* _session;
    uint16 _payload_size;
    uint32 _flags;
    uint64 _stream_id;
    uint8 _unitype;

    tls_handshakes _handshakes;
    http3_frames _frames;
    qpack_stream _qpack;
};

}  // namespace net
}  // namespace hotplace

#endif
