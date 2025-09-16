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

struct segment_t {
    const byte_t* stream;  // stream
    size_t size;           // size of stream
    size_t limit;          // segment size
    size_t pos;            // position
    size_t len;            // length

    segment_t() { clear(); }
    void clear() {
        stream = nullptr;
        size = 0;
        limit = 0;
        pos = 0;
        len = 0;
    }
    void calc(size_t bumper) {
        auto capacity = size - pos;
        auto l = (limit - bumper);
        len = (capacity < l) ? capacity : l;
    }
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
     * @param   QUIC FRAME CRYOTO
     * @param   tls_hs_type_t type [in]
     * @param   tls_direction_t dir [in]
     * @param   std::function<return_t(tls_handshake*, tls_direction_t)> func [in]
     */
    quic_packet_publisher& add(tls_hs_type_t type, tls_direction_t dir, std::function<return_t(tls_handshake*, tls_direction_t)> func = nullptr);
    /**
     * @brief   QUIC FRAME
     * @param   QUIC FRAME (1-RTT)
     * @param   quic_frame_t type [in]
     * @param   std::function<return_t(quic_frame*)> func [in]
     */
    quic_packet_publisher& add(quic_frame_t type, std::function<return_t(quic_frame*)> func = nullptr);
    /**
     * @brief   HTTP/3
     * @param   STREAM FRAME (1-RTT)
     * @param   uint64 stream_id [in]
     * @param   uint8 uni_type [in]
     * @param   h3_frame_t type [in]
     * @param   std::function<return_t(http3_frame*)> func [in]
     */
    quic_packet_publisher& add_stream(uint64 stream_id, uint8 uni_type, h3_frame_t type, std::function<return_t(http3_frame*)> func = nullptr);
    /**
     * @brief   QPACK ENDODER/DECODER STREAM
     * @param   uint64 stream_id [in]
     * @param   uint8 uni_type [in]
     * @param   std::function<return_t(qpack_stream&)> func [in]
     */
    quic_packet_publisher& add_stream(uint64 stream_id, uint8 uni_type, std::function<return_t(qpack_stream&)> func = nullptr);

    return_t publish(tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);

    return_t consume(quic_packet* packet, size_t paid, std::function<return_t(segment_t& segment)> func);

    tls_handshakes& get_handshakes();

   protected:
    return_t probe_spaces(std::set<protection_space_t>& spaces);
    return_t prepare_packet_cid(quic_packet* packet, protection_space_t space, tls_direction_t dir);
    return_t publish_space(protection_space_t space, tls_direction_t dir, uint32 flags, std::list<binary_t>& container);

   private:
    tls_session* _session;
    uint16 _payload_size;
    uint32 _flags;

    // QUIC CRYPTO FRAME
    tls_handshakes _handshakes;

    enum frame_entry_enum {
        frame_entry_quic = 1,
        frame_entry_h3frame = 2,
        frame_entry_qpack = 3,
    };
    // QUIC FRANE
    // QUIC STREAM FRAME (HTTP/3)
    struct frame_entry_t {
        frame_entry_enum how;

        quic_frame_t type;
        std::function<return_t(quic_frame*)> func;  // QUIC FRAME

        uint64 stream_id;
        uint8 uni_stream_type;

        http3_frame* frame;  // HTTP/3 FRAME
        binary_t bin;        // QPACK ENCODER/DECODER

        frame_entry_t() : how(frame_entry_quic), type(quic_frame_type_padding), stream_id(0), uni_stream_type(0), frame(nullptr) {}
    };
    std::list<frame_entry_t> _frame_layout;

    // segmentation (CRYPTO, STREAM)
    struct entry_t {
        frame_entry_enum how;

        quic_frame_t type;
        binary_t bin;
        size_t pos;
        uint64 stream_id;
        uint8 uni_stream_type;
        std::function<return_t(quic_frame*)> func;

        entry_t() : type(quic_frame_type_padding), pos(0), stream_id(0), uni_stream_type(0) {}
        ~entry_t() {}
    };
    critical_section _lock;
    std::map<protection_space_t, std::list<entry_t>> _segment;
};

}  // namespace net
}  // namespace hotplace

#endif
