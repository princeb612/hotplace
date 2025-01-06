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

#ifndef __HOTPLACE_SDK_NET_TLS_EXTENSION__
#define __HOTPLACE_SDK_NET_TLS_EXTENSION__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS extension
 */
class tls_extension {
   public:
    tls_extension(tls_session* session);
    tls_extension(const tls_extension& rhs);
    tls_extension(uint16 type, tls_session* session);
    ~tls_extension();

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    tls_session* get_session();
    void set_type(uint16 type);
    uint16 get_type();
    const range_t& get_header_range();
    uint16 get_length();
    size_t get_extsize();
    size_t endpos_extension();

    void addref();
    void release();

   protected:
    t_shared_reference<tls_extension> _shared;

    tls_session* _session;
    uint16 _type;
    range_t _header_range;  // range(header)
    uint16 _payload_len;    // size(payload)
    size_t _size;           // size(header) + size(payload)
};

class tls_extension_builder {
   public:
    tls_extension_builder();
    tls_extension_builder& set(tls_session* session);
    tls_extension_builder& set(uint16 type);
    tls_extension* build();

   private:
    tls_session* get_session();

    tls_session* _session;
    uint16 _type;
};

class tls_extension_unknown : public tls_extension {
   public:
    tls_extension_unknown(uint16 type, tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
};

/**
 * @brief   server_name (SNI, server name indicator, 0x0000)
 */
class tls_extension_sni : public tls_extension {
   public:
    tls_extension_sni(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    uint8 get_nametype();
    void set_hostname(const std::string& hostname);
    const binary_t& get_hostname();

   protected:
   private:
    uint8 _nametype;
    binary_t _hostname;
};

/**
 * @brief   status_request (0x0005)
 */
class tls_extension_status_request : public tls_extension {
   public:
    tls_extension_status_request(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    uint8 get_cert_status_type();
    void set_responderid_info(const binary_t& info);
    const binary_t& get_responderid_info();
    void set_request_ext_info(const binary_t& info);
    const binary_t& get_request_ext_info();

   protected:
   private:
    uint8 _cert_status_type;
    binary_t _responderid_info;
    binary_t _request_ext_info;
};

/**
 * @brief   supported_groups (0x000a)
 */
class tls_extension_supported_groups : public tls_extension {
   public:
    tls_extension_supported_groups(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    tls_extension_supported_groups& add_group(uint16 group);
    const binary_t& get_supported_groups();

   protected:
   private:
    binary_t _supported_groups;
};

/**
 * @brief   ec_point_formats (0x000b)
 */
class tls_extension_ec_point_formats : public tls_extension {
   public:
    tls_extension_ec_point_formats(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    tls_extension_ec_point_formats& add_format(uint8 fmt);
    const binary_t& get_formats();

   protected:
   private:
    binary_t _formats;
};

/**
 * @brief   signature_algorithms (0x000d)
 */
class tls_extension_signature_algorithms : public tls_extension {
   public:
    tls_extension_signature_algorithms(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    tls_extension_signature_algorithms& add_algorithm(uint16 alg);
    const binary_t& get_algorithms();

   protected:
   private:
    binary_t _algorithms;
};

/**
 * @brief   application_layer_protocol_negotiation (ALPN, 0x0010)
 */
class tls_extension_alpn : public tls_extension {
   public:
    tls_extension_alpn(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    const binary_t& get_protocols();

   protected:
   private:
    binary_t _protocols;
};

/**
 * @brief   compress_certificate (0x001b)
 */
class tls_extension_compress_certificate : public tls_extension {
   public:
    tls_extension_compress_certificate(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    tls_extension_compress_certificate& add_algorithm(uint16 alg);
    const binary_t& get_algorithms();

   protected:
   private:
    binary_t _algorithms;
};

/**
 * @brief   pre_shared_key (0x0029)
 */
class tls_extension_psk : public tls_extension {
   protected:
    tls_extension_psk(tls_session* session);
};

class tls_extension_client_psk : public tls_extension_psk {
   public:
    tls_extension_client_psk(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    uint16 _psk_identities_len;
    binary_t _psk_identity;
    uint32 _obfuscated_ticket_age;
    uint16 _psk_binders_len;
    binary_t _psk_binder;
    // size_t _offset_psk_binders_len;
};

class tls_extension_server_psk : public tls_extension_psk {
   public:
    tls_extension_server_psk(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    uint16 _selected_identity;
};

/**
 * @brief   supported_versions (0x002b)
 */
class tls_extension_supported_versions : public tls_extension {
   protected:
    tls_extension_supported_versions(tls_session* session);
};

class tls_extension_client_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_client_supported_versions(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    binary_t _versions;
};

class tls_extension_server_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_server_supported_versions(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    uint16 get_version();

   protected:
   private:
    uint16 _version;
};

/**
 * @brief   psk_key_exchange_modes (0x002d)
 */
class tls_extension_psk_key_exchange_modes : public tls_extension {
   public:
    tls_extension_psk_key_exchange_modes(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    uint8 _modes;
    binary_t _mode;
};

/**
 * @brief   tls1_ext_key_share (0x0033)
 */
class tls_extension_key_share : public tls_extension {
   protected:
    tls_extension_key_share(tls_session* session);
    return_t add_pubkey(uint16 group, const binary_t& pubkey, const keydesc& desc);
};

class tls_extension_client_key_share : public tls_extension_key_share {
   public:
    tls_extension_client_key_share(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    uint16 _key_share_len;
    std::list<uint16> _keys;
    std::map<uint16, binary_t> _keyshares;
};

class tls_extension_server_key_share : public tls_extension_key_share {
   public:
    tls_extension_server_key_share(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    uint16 _group;
    binary_t _pubkey;
};

/**
 * @brief   quic_transport_parameters (0x0039)
 */
class tls_extension_quic_transport_parameters : public tls_extension {
   public:
    tls_extension_quic_transport_parameters(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    std::list<uint64> _keys;
    std::map<uint64, binary_t> _params;
};

/**
 * @brief   application_layer_protocol_settings (ALPS, 0x4469)
 */
class tls_extension_alps : public tls_extension {
   public:
    tls_extension_alps(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

    const binary_t& get_alpn();

   protected:
   private:
    uint16 _alps_len;
    binary_t _alpn;
};

/**
 * @brief   encrypted_client_hello (0xfe0d)
 */
class tls_extension_encrypted_client_hello : public tls_extension {
   public:
    tls_extension_encrypted_client_hello(tls_session* session);

    virtual return_t read(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(binary_t& bin);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* s);

   protected:
   private:
    uint8 _client_hello_type;
    uint16 _kdf;
    uint16 _aead;
    uint8 _config_id;
    uint16 _enc_len;
    binary_t _enc;
    uint16 _enc_payload_len;
    binary_t _enc_payload;
};

}  // namespace net
}  // namespace hotplace

#endif
