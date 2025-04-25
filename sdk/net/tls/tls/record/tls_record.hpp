/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORD__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORD__

#include <sdk/base/basic/types.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

enum record_flag_t : uint32 {
    record_nochange_dtls_epochseq = (1 << 0),
};

class tls_record {
    friend class tls_record_application_data;
    friend class dtls13_ciphertext;

   public:
    virtual ~tls_record();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& bin, uint32 flags = 0);

    tls_session* get_session();  // session

    tls_content_type_t get_type();  // content type
    uint16 get_legacy_version();    // legacy version
    uint16 get_tls_version();
    void set_tls_version(uint16 version);

    bool is_dtls();
    uint16 get_key_epoch();        // DTLS key epoch
    uint64 get_dtls_record_seq();  // DTLS record sequence number

    virtual void operator<<(tls_record* record);
    virtual void operator<<(tls_handshake* handshake);

    void addref();
    void release();

   protected:
    tls_record(uint8 type, tls_session* session);

    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body);
    return_t do_write_header_internal(tls_direction_t dir, binary_t& bin, const binary_t& body);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual bool apply_protection();

    const range_t& get_header_range();
    uint16 get_body_size();
    size_t offsetof_header();
    size_t offsetof_body();

   private:
    uint8 _content_type;
    bool _cond_dtls;
    uint16 _dtls_epoch;
    uint64 _dtls_record_seq;  // uint48_t
    uint16 _bodysize;

    tls_session* _session;
    range_t _range;

    t_shared_reference<tls_record> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
