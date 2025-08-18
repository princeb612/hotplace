/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * reference
 *  https://github.com/martinduke/quic-test-vector
 *  https://quic.xargs.org/
 *
 * studying...
 *
 * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 * RFC 9001 Using TLS to Secure QUIC
 *
 * OpenSSL 3.2 and later features support for the QUIC transport protocol.
 * Currently, only client connectivity is supported.
 * This man page describes the usage of QUIC client functionality for both existing and new applications.
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKET__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKET__

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9000 17.  Packet Formats
 */
class quic_packet {
   public:
    quic_packet(tls_session* session);
    quic_packet(quic_packet_t type, tls_session* session);
    quic_packet(const quic_packet& rhs);
    virtual ~quic_packet();

    /**
     * @brief   type
     */
    uint8 get_type();
    /**
     * @brief   type
     * @param   uint8 hdr [in]
     * @param   uint8& type [out]
     * @param   bool& is_longheader [out]
     */
    void get_type(uint8 hdr, uint8& type, bool& is_longheader);
    /**
     * @brief   type
     * @param   uint8 type [in]
     * @param   uint8& hdr [out]
     * @param   bool& is_longheader [out]
     */
    void set_type(uint8 type, uint8& hdr, bool& is_longheader);
    /**
     * @brief   version
     */
    uint32 get_version();
    /**
     * @brief   DCID
     * @param   const binary& cid [in] DCID
     */
    quic_packet& set_dcid(const binary& cid);
    /**
     * @brief   SCID
     * @param   const binary& cid [in] SCID
     */
    quic_packet& set_scid(const binary& cid);
    /**
     * @brief   DCID
     */
    const binary_t& get_dcid();
    /**
     * @brief   SCID
     */
    const binary_t& get_scid();

    /**
     * @brief   read
     * @param   tls_direction_t dir [in]
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   size_t& pos [inout]
     * @remarks
     */
    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t read(tls_direction_t dir, const binary_t& bin, size_t& pos);

    /**
     * @brief   write
     * @param   tls_direction_t dir [in]
     * @param   binary_t& packet [out] header || ciphertext || tag
     */
    virtual return_t write(tls_direction_t dir, binary_t& packet);
    /**
     * @brief   write
     * @param   tls_direction_t dir
     * @param   binary_t& header [out]
     * @param   binary_t& ciphertext [out]
     * @param   binary_t& tag [out]
     */
    virtual return_t write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);

    virtual return_t write_unprotected_header(binary_t& packet);

    /*
     * @brief   set packet number
     * @param   uint32 pn [in]
     * @param   uint8 len [inopt]
     * @sample
     *          packet.set_pn(0x00000000, 1); // 00
     *          packet.set_pn(0x00000000, 4); // 00000000
     *          packet.set_pn(0x00000000);    // 00
     *          packet.set_pn(0x12345678, 4); // 12345678
     *          packet.set_pn(0x12345678);    // 12345678
     *
     * @remarks
     *          Initial, 1-RTT, Handshake, 0-RTT
     *          Packet Number (8..32)
     *          pn_length = (_ht & 0x03) + 1
     *
     */
    virtual void set_pn(uint32 pn, uint8 len = 0);
    uint8 get_pn_length();
    uint8 get_pn_length(uint8 ht);
    uint32 get_pn();

    quic_frames& get_quic_frames();
    quic_packet& operator<<(quic_frame* frame);

    /**
     * @remarks for a test
     */
    quic_packet& set_payload(const binary_t& payload);
    quic_packet& set_payload(const byte_t* stream, size_t size);
    const binary_t& get_payload();

    tls_session* get_session();
    void set_session(tls_session* session);

    void addref();
    void release();
    uint32 get_flags();

    // consider udp_max_payload_size
    fragmentation& get_fragment();

   protected:
    virtual return_t do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect);
    virtual return_t do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t pos_unprotect);
    return_t do_unprotect(tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, protection_space_t space);
    virtual return_t do_write_header(binary_t& packet, const binary_t& body = binary_t());
    virtual return_t do_estimate();
    virtual return_t do_write_body(tls_direction_t dir, binary_t& body);
    virtual return_t do_write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);

    /**
     * @brief   dump
     */
    void dump();

    /**
     * @brief   protect
     * @param   tls_direction_t dir [in]
     * @param   const binary_t& bin_ciphertext [in]
     * @param   protection_space_t space [in]
     * @param   uint8 hdr [in]
     * @param   uint8 pn_length [in]
     * @param   binary_t& bin_pn [inout]
     * @param   binary_t& bin_protected_header [inout]
     */
    return_t header_protect(tls_direction_t dir, const binary_t& bin_ciphertext, protection_space_t space, uint8 hdr, uint8 pn_length, binary_t& bin_pn,
                            binary_t& bin_protected_header);
    /**
     * @brief   unprotect
     * @param   tls_direction_t dir [in]
     * @param   const byte_t* stream [in] packet number ...
     * @param   size_t size [in]
     * @param   protection_space_t space [in]
     * @param   uint8& hdr [inout]
     * @param   uint32& pn [out]
     * @param   binary_t& bin_payload [inout]
     */
    return_t header_unprotect(tls_direction_t dir, const byte_t* stream, size_t size, protection_space_t space, uint8& hdr, uint32& pn, binary_t& bin_payload);

    t_shared_reference<quic_packet> _shared;

    /**
     * @brief   version
     */
    quic_packet& set_version();

   protected:
    uint8 _type;
    uint8 _ht;              // header type, public flag
    tls_session* _session;  // session
    uint32 _version;        // version
    uint32 _pn;             // packet number
    binary_t _dcid;         // destination
    binary_t _scid;         // source
    binary_t _payload;
    binary_t _tag;
    quic_frames _frames;

    // consider udp_max_payload_size
    fragmentation _fragment;
};

/**
 * @brief   QUIC packet MSB
 * @param   uint32 version [in] see quic_version_t
 * @param   uint8 hdr [in]
 * @param   uint8& type [out] see quic_packet_t
 * @param   bool& is_longheader [out]
 */
void quic_packet_get_type(uint32 version, uint8 hdr, uint8& type, bool& is_longheader);
/**
 * @brief   QUIC packet MSB
 * @param   uint32 version
 * @param   uint8 type
 * @param   uint8& hdr
 * @param   bool& is_longheader
 */
void quic_packet_set_type(uint32 version, uint8 type, uint8& hdr, bool& is_longheader);

return_t quic_read_packet(uint8& type, tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
return_t quic_read_packet(uint8& type, tls_session* session, tls_direction_t dir, const binary_t& packet);

/**
 *                              TYPE VERSION len(DCID) DCID len(SCID) SCID TOKEN PN
 *  quic_packet_type_initial      O     O       O        O       O      O     O   O
 *  quic_packet_type_handshake    O     O       O        O       O      O         O
 *  quic_packet_type_1_rtt        O                      O                        O
 */
uint32 estimate_quic_packet_size(uint8 type, uint8 dcidlen, uint8 scidlen, uint8 tokenlen, uint8 pnl, uint16 payload, uint8 taglen);

}  // namespace net
}  // namespace hotplace

#endif
