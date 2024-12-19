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

#ifndef __HOTPLACE_SDK_NET_QUIC__
#define __HOTPLACE_SDK_NET_QUIC__

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9000 17.  Packet Formats
 * 17.2.  Long Header Packets
 * 17.3.  Short Header Packets
 */
enum quic_packet_field_t {
    quic_packet_field_hf = 0x80,         // RFC 9000 Figure 13, Header Form
    quic_packet_field_fb = 0x40,         // RFC 9000 Figure 13, Fixed Bit
    quic_packet_field_mask_lh = 0x30,    // RFC 9000 Figure 13, Long Packet Type
    quic_packet_field_initial = 0x00,    // RFC 9000 Table 5, 17.2.2, Initial Packet
    quic_packet_field_0_rtt = 0x10,      // RFC 9000 Table 5, 17.2.3, 0-RTT
    quic_packet_field_handshake = 0x20,  // RFC 9000 Table 5, 17.2.4, Handshake Packet
    quic_packet_field_retry = 0x30,      // RFC 9000 Table 5, 17.2.5, Retry Packet
    quic_packet_field_sb = 0x20,         // RFC 9000 Figure 19: 1-RTT Packet, 17.4.  Latency Spin Bit
    quic_packet_field_kp = 0x04,         // RFC 9000 Figure 19: 1-RTT Packet, Key Phase
    quic_packet_field_mask_pnl = 0x03,   // RFC 9000 Figure 19: 1-RTT Packet, Packet Number Length
};

enum quic_packet_t {
    quic_packet_type_version_negotiation = 1,  // RFC 9000 17.2.1.  Version Negotiation Packet
    quic_packet_type_initial = 2,              // RFC 9000 17.2.2.  Initial Packet
    quic_packet_type_0_rtt = 3,                // RFC 9000 17.2.3.  0-RTT
    quic_packet_type_handshake = 4,            // RFC 9000 17.2.4.  Handshake Packet
    quic_packet_type_retry = 5,                // RFC 9000 17.2.5.  Retry Packet
    quic_packet_type_1_rtt = 6,                // RFC 9000 17.3.1.  1-RTT Packet
};

/*
 * RFC 9000 12.4.  Frames and Frame Types
 */
enum quic_frame_t {
    quic_frame_padding = 0,                  // RFC 9000 19.1  IH01
    quic_frame_ping = 1,                     // RFC 9000 19.2  IH01
    quic_frame_ack = 2,                      // RFC 9000 19.3  IH_1 0x02-0x03
    quic_frame_reset_stream = 4,             // RFC 9000 19.4  __01
    quic_frame_stop_sending = 5,             // RFC 9000 19.5  __01
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

/**
 * RFC 9000 18.  Transport Parameter Encoding
 */
enum quic_param_t {
    quic_param_original_destination_connection_id = 0x00,
    quic_param_max_idle_timeout = 0x01,
    quic_param_stateless_reset_token = 0x02,
    quic_param_max_udp_payload_size = 0x03,
    quic_param_initial_max_data = 0x04,
    quic_param_initial_max_stream_data_bidi_local = 0x05,
    quic_param_initial_max_stream_data_bidi_remote = 0x06,
    quic_param_initial_max_stream_data_uni = 0x07,
    quic_param_initial_max_streams_bidi = 0x08,
    quic_param_initial_max_streams_uni = 0x09,
    quic_param_ack_delay_exponent = 0x0a,
    quic_param_max_ack_delay = 0x0b,
    quic_param_disable_active_migration = 0x0c,
    quic_param_preferred_address = 0x0d,
    quic_param_active_connection_id_limit = 0x0e,
    quic_param_initial_source_connection_id = 0x0f,
    quic_param_retry_source_connection_id = 0x10,
};

/**
 * RFC 9000 20.  Error Codes
 */
enum h3_errorcodes_t {
    h3_no_error = 0x00,
    h3_internal_error = 0x01,
    h3_connection_refused = 0x02,
    h3_flow_control_error = 0x03,
    h3_stream_limit_error = 0x04,
    h3_stream_state_error = 0x05,
    h3_final_size_error = 0x06,
    h3_frame_encoding_error = 0x07,
    h3_transport_parameter_error = 0x08,
    h3_connection_id_limit_error = 0x09,
    h3_protocol_violation = 0x0a,
    h3_invalid_token = 0x0b,
    h3_application_error = 0x0c,
    h3_crypto_buffer_exceeded = 0x0d,
    h3_key_update_error = 0x0e,
    h3_aead_limit_reached = 0x0f,
    h3_no_viable_path = 0x10,
    h3_crypto_error = 0x0100,  // 0x0100-0x01ff
};

/**
 */

/**
 * RFC 9000 Figure 22: Preferred Address Format
 */
// struct preferred_address {
//     uint32 ipv4addr;
//     uint16 ipv4port;
//     uint128 ipv6addr;
//     uint16 ipv6port;
//     binary_t cid;
//     uint128 stateless_reset_token;
// };

enum quic_initial_keys_t : uint16 {
    quic_original_dcid = 0,
    quic_initial_secret = 1,  // initial secret
    quic_client_secret = 2,   // client initial secret
    quic_server_secret = 3,   // server initial secret
    quic_client_key = 4,      // client initial key
    quic_server_key = 5,      // server initial key
    quic_client_iv = 6,       // client initial iv
    quic_server_iv = 7,       // server initial iv
    quic_client_hp = 8,       // client header protection key
    quic_server_hp = 9,       // server header protection key
};

/**
 * @brief   RFC 9001 5.  Packet Protection
 */
class quic_protection {
   public:
    /**
     * @brief   constructor
     * @param   const binary_t& salt [in] DCID
     * @param   uint32 mode [inopt] see tls_mode_t
     */
    quic_protection(const binary_t& salt, uint32 mode = -1);
    quic_protection(const binary_t& salt, const binary_t& context, uint32 mode = -1);

    /**
     * @brief   get item
     * @param   quic_initial_keys_t mode [in]
     */
    const binary_t& get_item(quic_initial_keys_t mode);
    /**
     * @brief   get item
     * @param   quic_initial_keys_t mode [in]
     * @param   binary_t& item [out]
     */
    void get_item(quic_initial_keys_t mode, binary_t& item);

    /**
     * @brief   header protection mask
     * @param   uint32 mode [in]
     * @param   const byte_t* sample [in]
     * @param   size_t size_sample [in]
     * @param   binary_t& mask [out]
     */
    return_t hpmask(uint32 mode, const byte_t* sample, size_t size_sample, binary_t& mask);
    /**
     * @brief   header protection
     * @param   uint32 mode [in]
     * @param   const binary_t& mask [in]
     * @param   byte_t& ht [inout]
     * @param   binary_t& bin_pn [out]
     */
    return_t hpencode(uint32 mode, const binary_t& mask, byte_t& ht, binary_t& bin_pn);
    /**
     * @brief   encrypt payload
     * @param   uint32 mode [in]
     * @param   uint64 pn [in]
     * @param   const binary_t& payload [in]
     * @param   binary_t& encrypted [out]
     * @param   const binary_t& aad [in]
     * @param   binary_t& tag [out]
     */
    return_t encrypt(uint32 mode, uint64 pn, const binary_t& payload, binary_t& encrypted, const binary_t& aad, binary_t& tag);
    /**
     * @brief   decrypt payload
     * @param   uint32 mode [in]
     * @param   uint64 pn [in]
     * @param   const binary_t& payload [in]
     * @param   binary_t& decrypted [out]
     * @param   const binary_t& aad [in]
     * @param   const binary_t& tag [in]
     */
    return_t decrypt(uint32 mode, uint64 pn, const binary_t& payload, binary_t& decrypted, const binary_t& aad, const binary_t& tag);
    /**
     * @brief   retry packet
     * @param   const quic_packet_retry& retry_packet [in]
     * @param   binary_t& tag [out]
     */
    return_t retry_integrity_tag(const quic_packet_retry& retry_packet, binary_t& tag);

    void addref();
    void release();

   protected:
    t_shared_reference<quic_protection> _shared;
    std::map<uint16, binary_t> _kv;
    SSL* _ssl;

    /**
     * @brief   initial keys calc
     * @param   const binary_t& salt [in]
     * @param   const binary_t& context [in]
     * @param   uint32 mode [in]
     */
    return_t calc(const binary_t& salt, const binary_t& context, uint32 mode);
};

/**
 * RFC 9000 17.  Packet Formats
 */
class quic_packet {
   public:
    quic_packet();
    quic_packet(quic_packet_t type);
    quic_packet(const quic_packet& rhs);
    ~quic_packet();

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

    void attach(quic_protection* keys);
    quic_protection* get_protection();

    /**
     * @brief   read
     * @param   const byte_t* stream [in]
     * @param   size_t size [in]
     * @param   size_t& pos [inout]
     * @param   uint32 mode [inopt]
     * @remarks
     *          // sketch
     *
     *          payload pl;
     *          // set layout
     *          // pl << ... << new payload_member(binary_t(), "payload");
     *          pl.read(stream, size, pos);
     *          payload = pl.select("payload")->get_variant().to_binary(payload);
     *
     *          // unprotect header
     *          pl.write(unprotected_header);
     *          // decrypt payload
     *          binary_append(aad, &payload[0], 0x10);
     *          binary_append(tag, &payload[size - 0x10], 0x10);
     *          binary_load(bin_pn, 8, pn, hton64);
     *          for (int i = 0; i < 8; i++) {
     *              iv[i + 12 - 8] ^= bin_pn[i];
     *          }
     *          crypt.open(&handle, "aes-128-gcm", client_key, client_iv);
     *          crypt.decrypt2(handle, &payload[0], payload.size() - 0x10, payload_decrypted, &aad, &tag);
     *          crypt.close(handle);
     *
     *          set_payload(payload_decrypted);  // replace
     */
    virtual return_t read(const byte_t* stream, size_t size, size_t& pos, uint32 mode = 0);
    virtual return_t read(const binary_t& bin, size_t& pos, uint32 mode = 0);

    /**
     * @brief   write
     * @param   binary_t& packet [out]
     * @param   uint32 mode [inopt]  RFC 9001 5.4.  Header Protection
     *                               see tls_mode_t
     * @remarks
     *          // sketch
     *
     *          // unprotected_header
     *          packet.write(unprotected_header);
     *
     *          // encrypt
     *          binary_load(bin_pn, 8, pn, hton64);
     *          for (int i = 0; i < 8; i++) {
     *              client_iv[i + 12 - 8] ^= bin_pn[i];
     *          }
     *          crypt.open(&handle, "aes-128-gcm", client_key, client_iv);
     *          crypt.encrypt2(handle, frame, encrypted_frame, &unprotected_header, &tag);
     *          crypt.close(handle);
     *
     *          // protected header
     *          packet.set_payload(encrypted_frame); // sample
     *          packet.write(unprotected_header, tls_mode_client);
     *
     *          // unprotected_header + encrypted_frame frame + tag
     *          binary_append(bin_packet, protected_header);
     *          binary_append(bin_packet, encrypted_frame);
     *          binary_append(bin_packet, tag);
     */
    virtual return_t write(binary_t& packet, uint32 mode = 0);

    /**
     * @brief   dump
     * @param   stream_t* s [in]
     */
    virtual void dump(stream_t* s);

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

   protected:
    uint8 _type;
    uint8 _ht;        // header type, public flag
    uint32 _version;  // version
    binary_t _dcid;   // destination
    binary_t _scid;   // source

    uint32 _pn;
    binary_t _payload;

    quic_protection* _keys;
};

/**
 * @brief   RFC 9000 17.2.1.  Version Negotiation Packet
 */
class quic_packet_version_negotiation : public quic_packet {
   public:
    quic_packet_version_negotiation();
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
    quic_packet_initial();
    quic_packet_initial(const quic_packet_initial& rhs);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos, uint32 mode = 0);
    virtual return_t write(binary_t& packet, uint32 mode = 0);
    virtual return_t write(binary_t& header, binary_t& encrypted, binary_t& tag, uint32 mode = 0);
    virtual void dump(stream_t* s);

    quic_packet_initial& set_token(const binary_t& token);
    const binary_t& get_token();
    uint64 get_length();

   protected:
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
};

/**
 * @breif   RFC 9000 17.2.3.  0-RTT
 */
class quic_packet_0rtt : public quic_packet {
   public:
    quic_packet_0rtt();
    quic_packet_0rtt(const quic_packet_0rtt& rhs);

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
 * @brief   17.2.4.  Handshake Packet
 */
class quic_packet_handshake : public quic_packet {
   public:
    quic_packet_handshake();
    quic_packet_handshake(const quic_packet_handshake& rhs);

   protected:
   private:
    /**
     * Figure 17: Handshake Protected Packet
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
};

class quic_packet_retry : public quic_packet {
   public:
    quic_packet_retry();
    quic_packet_retry(const quic_packet_retry& rhs);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos, uint32 mode = 0);
    virtual return_t write(binary_t& packet, uint32 mode = 0);
    virtual void dump(stream_t* s);

    quic_packet_retry& set_retry_token(const binary_t& token);
    quic_packet_retry& set_integrity_tag(const binary_t& tag);

    const binary_t& get_retry_token();
    const binary_t& get_integrity_tag();

   protected:
   private:
    /**
     * Figure 18: Retry Packet
     *  Retry Token (..),
     *  Retry Integrity Tag (128),
     */
    binary_t _retry_token;
    binary_t _retry_integrity_tag;
};

class quic_packet_1rtt : public quic_packet {
   protected:
    quic_packet_1rtt();
    quic_packet_1rtt(const quic_packet_1rtt& rhs);

   private:
    /**
     * Figure 19: 1-RTT Packet
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
};

class tls_session;
/**
 * @brief   read
 * @param   stream_t* s [out]
 * @param   tls_session* session [in]
 * @param   const byte_t** stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 */
return_t quic_dump_frame(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role = role_server);
return_t quic_dump_frame(stream_t* s, tls_session* session, const binary_t frame, size_t& pos, tls_role_t role = role_server);

/**
 * @brief   an integer value using the variable-length encoding
 * @param   const byte_t* stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 * @param   uint64& value [out]
 * @remarks RFC 9000
 *            16.  Variable-Length Integer Encoding
 *              Table 4: Summary of Integer Encodings
 *            17.1.  Packet Number Encoding and Decoding
 *            A.1.  Sample Variable-Length Integer Decoding
 *              Figure 45: Sample Variable-Length Integer Decoding Algorithm
 */
return_t quic_read_vle_int(const byte_t* stream, size_t size, size_t& pos, uint64& value);
/**
 * @brief   an integer value using the variable-length encoding
 * @param   uint64 value [in]
 * @param   binary_t& bin [out]
 * @remarks RFC 9000
 *            16.  Variable-Length Integer Encoding
 *              Table 4: Summary of Integer Encodings
 *            17.1.  Packet Number Encoding and Decoding
 *            A.1.  Sample Variable-Length Integer Decoding
 *              Figure 45: Sample Variable-Length Integer Decoding Algorithm
 */
return_t quic_write_vle_int(uint64 value, binary_t& bin);

return_t quic_length_vle_int(uint64 value, uint8& length);
uint8 quic_length_vle_int(uint64 value);

/**
 * @brief   RFC 9000
 *            17.1.  Packet Number Encoding and Decoding
 *            A.2.  Sample Packet Number Encoding Algorithm
 *              Figure 46: Sample Packet Number Encoding Algorithm
 */
return_t encode_packet_number(uint64 full_pn, uint64 largest_acked, uint64& represent, uint8& nbits);

/**
 * @brief   RFC 9000
 *            17.1.  Packet Number Encoding and Decoding
 *            A.3.  Sample Packet Number Decoding Algorithm
 *              Figure 47: Sample Packet Number Decoding Algorithm
 */
return_t decode_packet_number(uint64 largest_pn, uint64 truncated_pn, uint8 pn_nbits, uint64& value);

/**
 * @brief   QUIC variable length integer encoding
 * @sa      payload_member
 * @remarks
 *          sketch
 *          // Token Length (i),
 *          // Token (..),
 *          // 05 74 6F 6B 65 6E -- -- -- -- -- -- -- -- -- -- | .token
 *
 *          // payload set_reference_value interface
 *          payload pl1;
 *          binary_t bin1;
 *          pl1 << new payload_member(new quic_encoded(5)) << new payload_member("token");
 *          pl1.write(bin1);
 *
 *          payload pl2;
 *          binary_t bin2;
 *          pl2 << new payload_member(new quic_encoded(int(0)), "len") << new payload_member(binary_t(), "token");
 *          pl2.set_reference_value("token", "len");  // length of "token" is value of "len"
 *          pl2.read(bin1);
 *          pl2.write(bin2);
 *
 *          // simple
 *          payload p3;
 *          binary_t bin3;
 *          pl3 << new payload_member(new quic_encoded("token"));
 *          pl3.write(bin3);
 *
 *          payload pl4;
 *          binary_t bin4;
 *          pl4 << new payload_member(new quic_encoded);
 *          pl4.read(bin3);
 *          pl4.write(bin4);
 */
class quic_encoded : public payload_encoded {
   public:
    quic_encoded();
    quic_encoded(const quic_encoded& rhs);
    quic_encoded(quic_encoded&& rhs);
    /**
     * @brief   integers in the range 0 to 2^62-1
     */
    quic_encoded(uint64 data);
    /**
     * @brief   integer + data
     */
    quic_encoded(const char* data);
    quic_encoded(const std::string& data);
    quic_encoded(const binary_t& data);

    quic_encoded& set(const char* data);
    quic_encoded& set(const std::string& data);
    quic_encoded& set(const binary_t& data);

    virtual size_t lsize();
    virtual size_t value();
    virtual const byte_t* data();
    virtual void write(binary_t& target);

    virtual size_t lsize(const byte_t* stream, size_t size);
    virtual size_t value(const byte_t* stream, size_t size);
    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);

    virtual variant& get_variant();

   protected:
    bool _datalink;
    uint64 _len;
    variant _data;
};

}  // namespace net
}  // namespace hotplace

#endif
