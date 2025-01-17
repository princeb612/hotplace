/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_RECORD__
#define __HOTPLACE_SDK_NET_TLS1_RECORD__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/net/tls1/tls.hpp>

namespace hotplace {
namespace net {

class tls_record {
   public:
    ~tls_record();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    tls_session* get_session();  // session

    tls_content_type_t get_type();  // content type
    uint16 get_legacy_version();    // legacy version

    bool is_dtls();
    uint16 get_key_epoch();                 // DTLS key epoch
    const binary_t& get_dtls_record_seq();  // DTLS record sequence number

    void addref();
    void release();

   protected:
    tls_record(uint8 type, tls_session* session);

    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream = nullptr);
    // virtual return_t do_encrypt(tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, stream_t* debugstream = nullptr);
    // virtual return_t do_decrypt(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, binary_t& plaintext, stream_t* debugstream = nullptr);
    virtual return_t do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    const range_t& get_header_range();
    uint16 get_body_size();
    size_t offsetof_header();
    size_t offsetof_body();

    uint8 _content_type;
    uint16 _legacy_version;
    bool _cond_dtls;
    uint16 _key_epoch;
    binary_t _dtls_record_seq;
    uint16 _bodysize;

    tls_session* _session;
    range_t _range;

    t_shared_reference<tls_record> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
