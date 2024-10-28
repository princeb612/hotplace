/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * studying...
 *
 * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 * RFC 9001 Using TLS to Secure QUIC
 *
 * OpenSSL 3.2 and later features support for the QUIC transport protocol.
 * Currently, only client connectivity is supported.
 * This man page describes the usage of QUIC client functionality for both existing and new applications.
 */

#ifndef __HOTPLACE_SDK_NET_QUIC__
#define __HOTPLACE_SDK_NET_QUIC__

#include <sdk/net/quic/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9000 17.  Packet Formats
 * 17.2.  Long Header Packets
 */
enum quic_packet_field_t {
    quic_packet_field_hf = 0x80,         // RFC 9000 Figure 13
    quic_packet_field_fb = 0x40,         // RFC 9000 Figure 13
    quic_packet_field_mask_t = 0x30,     // RFC 9000 Figure 13
    quic_packet_field_initial = 0x00,    // RFC 9000 17.2.2.  Initial Packet
    quic_packet_field_0_rtt = 0x10,      // RFC 9000 17.2.3.  0-RTT
    quic_packet_field_handshake = 0x20,  // RFC 9000 17.2.4.  Handshake Packet
    quic_packet_field_retry = 0x30,      // RFC 9000 17.2.5.  Retry Packet
    quic_packet_field_mask_s = 0x0f,     // RFC 9000 Figure 13
    quic_packet_field_mask_pnl = 0x03,   // RFC 9000 Initial Packet, 0-RTT, Handshake Packet, 1-RTT Packet
    quic_packet_field_spin = 0x20,       // RFC 9000 17.4.  Latency Spin Bit
    quic_packet_field_key_phase = 0x04,  // RFC 9000 17.3.  Short Header Packets
};

enum quic_packet_t {
    quic_packet_version_negotiation = 1,
    quic_packet_initial = 2,
    quic_packet_0_rtt = 3,
    quic_packet_handshake = 4,
    quic_packet_retry = 5,
    quic_packet_1_rtt = 6,
};

/*
 * RFC 9000 12.4.  Frames and Frame Types
 */
enum quic_frame_t {
    quic_frame_padding = 0,                  // RFC 9000 19.1  IH01
    quic_frame_ping = 1,                     // RFC 9000 19.2  IH01
    quic_frame_ack = 2,                      // RFC 9000 19.3  IH_1 0x02-0x03
    quic_frame_reset_stream = 4,             // RFC 9000 19.4  __01
    quic_frame_stop_pending = 5,             // RFC 9000 19.5  __01
    quic_frame_crypto = 6,                   // RFC 9000 19.6  IH_1
    quic_frame_new_token = 7,                // RFC 9000 19.7  ___1
    quic_frame_stream = 8,                   // RFC 9000 19.8  __01 0x08-0x0f
    quic_frame_max_data = 0x10,              // RFC 9000 19.9  __01
    quic_frame_max_stream_data = 0x11,       // RFC 9000 19.10 __01
    quic_frame_max_streams = 0x12,           // RFC 9000 19.11 __01 0x12-0x13
    quic_frame_data_blocked = 0x14,          // RFC 9000 19.12 __01
    quic_frame_stream_data_blocked = 0x15,   // RFC 9000 19.13 __01
    quic_frame_stream_blocked = 0x16,        // RFC 9000 19.14 __01 0x16-0x17
    quic_frame_new_connection_id = 0x18,     // RFC 9000 19.15 __01
    quic_frame_retire_connection_id = 0x19,  // RFC 9000 19.16 __01
    quic_frame_path_challenge = 0x1a,        // RFC 9000 19.17 __01
    quic_frame_path_response = 0x1b,         // RFC 9000 19.18 ___1
    quic_frame_connection_close = 0x1c,      // RFC 9000 19.19 ih01 0x1c-0x1d
    quic_frame_handshake_done = 0x1e,        // RFC 9000 19.20 ___1
};

class quic_packet {
   public:
    quic_packet();
    quic_packet(quic_packet_t type);
    quic_packet(const quic_packet& rhs);

    quic_packet& set_version(uint32 version);
    uint32 get_version();
    void set_dcid(const binary& cid);
    void set_scid(const binary& cid);
    const binary_t& get_dcid();
    const binary_t& get_scid();
    uint8 get_type();

    /**
     * @brief   read
     * @param   byte_t* stream [in]
     * @param   size_t size [in]
     * @param   size_t& pos [inout]
     */
    virtual return_t read(byte_t* stream, size_t size, size_t& pos);
    /**
     * @brief   write
     * @param   binary_t& packet [out]
     */
    virtual return_t write(binary_t& packet);
    /**
     * @brief   dump
     * @param   stream_t* s [in]
     */
    virtual void dump(stream_t* s);

   protected:
    uint8 _type;
    uint32 _version;
    binary_t _dcid;
    binary_t _scid;
};

class quick_frame {
   public:
    quick_frame();
    quick_frame(const quick_frame& rhs);
};

class quick_frame_padding : public quick_frame {
   public:
    quick_frame_padding();
    quick_frame_padding(const quick_frame_padding& rhs);
};

}  // namespace net
}  // namespace hotplace

#endif
