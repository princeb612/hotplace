/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_RECORD__
#define __HOTPLACE_SDK_NET_TLS_RECORD__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/net/tls1/tls.hpp>

namespace hotplace {
namespace net {

class tls_record {
   public:
    ~tls_record();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    tls_session* get_session();
    tls_content_type_t get_type();
    uint16 get_legacy_version();
    bool is_dtls();
    uint16 get_key_epoch();
    const binary_t& get_dtls_record_seq();
    uint16 get_length();
    const range_t& get_header_range();

    void addref();
    void release();

   protected:
    tls_record(uint8 type, tls_session* session);

    uint8 _content_type;
    uint16 _legacy_version;
    bool _cond_dtls;
    uint16 _key_epoch;
    binary_t _dtls_record_seq;
    uint16 _len;

    tls_session* _session;
    range_t _range;

    t_shared_reference<tls_record> _shared;
};

class tls_record_builder {
   public:
    tls_record_builder();

    tls_record_builder& set(tls_session* session);
    tls_record_builder& set(uint8 type);
    tls_record* build();

    tls_session* get_session();
    uint8 get_type();

   private:
    tls_session* _session;
    uint8 _type;
};

class tls_change_cipher_spec : public tls_record {
   public:
    tls_change_cipher_spec(tls_session* session);

    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
};

class tls_alert : public tls_record {
   public:
    tls_alert(tls_session* session);

    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_plaintext(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    uint8 _level;
    uint8 _desc;
};

class tls_handshake : public tls_record {
   public:
    tls_handshake(tls_session* session);
    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    void addref();
    void release();

   protected:
    t_shared_reference<tls_handshake> _shared;
    // std::list<tls_extension*> _extensions;
};

class tls_application_data : public tls_record {
   public:
    tls_application_data(tls_session* session);
    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    void addref();
    void release();

   protected:
    t_shared_reference<tls_application_data> _shared;
    // std::list<tls_extension*> _extensions;
};

class tls_ack : public tls_record {
   public:
    tls_ack(tls_session* session);

    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
};

class tls_record_unknown : public tls_record {
   public:
    tls_record_unknown(uint8 type, tls_session* session);

    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
};

class dtls13_ciphertext : public tls_record {
   public:
    dtls13_ciphertext(uint8 type, tls_session* session);

    virtual return_t read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

   protected:
    uint16 _sequence;
    uint8 _sequence_len;
    size_t _offset_encdata;
};

}  // namespace net
}  // namespace hotplace

#endif
