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

#ifndef __HOTPLACE_SDK_NET_QUIC_PACKET__
#define __HOTPLACE_SDK_NET_QUIC_PACKET__

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/types.hpp>
#include <sdk/net/tls1/types.hpp>

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
     * @param   uint32 version [in] 1
     */
    quic_packet& set_version(uint32 version);
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

    virtual return_t write_header(binary_t& packet);

    return_t read_common_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t write_common_header(binary_t& packet);

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
    /**
     * @remarks payload
     *          Initial, 1-RTT, Handshake, 0-RTT
     */
    quic_packet& set_payload(const binary_t& payload);
    quic_packet& set_payload(const byte_t* stream, size_t size);
    const binary_t& get_payload();

    tls_session* get_session();

    void addref();
    void release();

   protected:
    /**
     * @brief   dump
     */
    void dump();

    /**
     * @brief   protect
     * @param   tls_direction_t dir [in]
     * @param   const binary_t& bin_ciphertext [in]
     * @param   protection_level_t level [in]
     * @param   uint8 hdr [in]
     * @param   uint8 pn_length [in]
     * @param   binary_t& bin_pn [inout]
     * @param   binary_t& bin_protected_header [inout]
     */
    return_t header_protect(tls_direction_t dir, const binary_t& bin_ciphertext, protection_level_t level, uint8 hdr, uint8 pn_length, binary_t& bin_pn,
                            binary_t& bin_protected_header);
    /**
     * @brief   unprotect
     * @param   tls_direction_t dir [in]
     * @param   const byte_t* stream [in] packet number ...
     * @param   size_t size [in]
     * @param   protection_level_t level [in]
     * @param   uint8& hdr [inout]
     * @param   uint32& pn [out]
     * @param   binary_t& bin_payload [inout]
     */
    return_t header_unprotect(tls_direction_t dir, const byte_t* stream, size_t size, protection_level_t level, uint8& hdr, uint32& pn, binary_t& bin_payload);

    t_shared_reference<quic_packet> _shared;

    tls_session* _session;

    uint8 _type;
    uint8 _ht;        // header type, public flag
    uint32 _version;  // version
    binary_t _dcid;   // destination
    binary_t _scid;   // source

    uint32 _pn;
    binary_t _payload;
};

/**
 * @brief   RFC 9000 17.2.1.  Version Negotiation Packet
 */
class quic_packet_version_negotiation : public quic_packet {
   public:
    quic_packet_version_negotiation(tls_session* session);
    quic_packet_version_negotiation(const quic_packet_version_negotiation& rhs);

   protected:
   private:
    /**
     * Figure 14: Version Negotiation Packet
     *  Supported Version (32) ...,
     */
    std::vector<uint32> _version;
};

/**
 * @brief   RFC 9000 17.2.2.  Initial Packet
 */
class quic_packet_initial : public quic_packet {
   public:
    quic_packet_initial(tls_session* session);
    quic_packet_initial(const quic_packet_initial& rhs);

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);

    quic_packet_initial& set_token(const binary_t& token);
    const binary_t& get_token();
    uint64 get_length();

   protected:
    virtual void dump();

   private:
    /**
     * Figure 15: Initial Packet
     *  Token Length (i),
     *  Token (..),
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
    binary_t _token;
    uint64 _length;
    uint8 _sizeof_length;
};

/**
 * @breif   RFC 9000 17.2.3.  0-RTT
 */
class quic_packet_0rtt : public quic_packet {
   public:
    quic_packet_0rtt(tls_session* session);
    quic_packet_0rtt(const quic_packet_0rtt& rhs);

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);

   protected:
   private:
    /**
     * Figure 16: 0-RTT Packet
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
    uint32 _pn;
    binary_t _payload;
};

/**
 * @brief   RFC 9000 17.2.4.  Handshake Packet
 */
class quic_packet_handshake : public quic_packet {
   public:
    quic_packet_handshake(tls_session* session);
    quic_packet_handshake(const quic_packet_handshake& rhs);

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);

    uint64 get_length();

   protected:
    virtual void dump();

   private:
    /**
     * Figure 17: Handshake Protected Packet
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
    uint64 _length;
    uint8 _sizeof_length;
};

/**
 * @brief   RFC 9000 17.2.5.  Retry Packet
 */
class quic_packet_retry : public quic_packet {
   public:
    quic_packet_retry(tls_session* session);
    quic_packet_retry(const quic_packet_retry& rhs);

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& packet);

    quic_packet_retry& set_retry_token(const binary_t& token);
    quic_packet_retry& set_integrity_tag(const binary_t& tag);

    const binary_t& get_retry_token();
    const binary_t& get_integrity_tag();

   protected:
    virtual void dump();

    /**
     * @brief   retry packet
     * @param   const quic_packet_retry& retry_packet [in]
     * @param   binary_t& tag [out]
     */
    return_t retry_integrity_tag(const quic_packet_retry& retry_packet, binary_t& tag);

   private:
    /**
     * Figure 18: Retry Packet
     *  Retry Token (..),
     *  Retry Integrity Tag (128),
     */
    binary_t _retry_token;
    binary_t _retry_integrity_tag;
};

/**
 * @brief   RFC 9000 17.3.1.  1-RTT Packet
 * @remarks
 *          Figure 19: 1-RTT Packet
 *           Packet Number (8..32),
 *           Packet Payload (8..),
 */
class quic_packet_1rtt : public quic_packet {
   public:
    quic_packet_1rtt(tls_session* session);
    quic_packet_1rtt(const quic_packet_1rtt& rhs);

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);
};

return_t quic_read_packet(uint8& type, tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
return_t quic_read_packet(uint8& type, tls_session* session, tls_direction_t dir, const binary_t& packet);

}  // namespace net
}  // namespace hotplace

#endif
