/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKE__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKE__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/net/tls1/tls.hpp>

namespace hotplace {
namespace net {

class tls_handshake {
   public:
    tls_handshake(tls_hs_type_t type, tls_session* session);
    ~tls_handshake();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
    virtual return_t dump(const byte_t* stream, size_t size, stream_t* debugstream = nullptr);

    void addref();
    void release();

    return_t add(tls_extension* extension, bool upref = false);
    tls_handshake& operator<<(tls_extension* extension);

    tls_hs_type_t get_type();
    tls_session* get_session();
    size_t get_header_size();
    const range_t& get_header_range();
    size_t offsetof_header();
    size_t offsetof_body();
    uint32 get_length();

   protected:
    virtual return_t do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_preprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream = nullptr);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream = nullptr);
    virtual return_t do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
    virtual return_t dump_header(const byte_t* stream, size_t size, stream_t* debugstream = nullptr);
    virtual return_t do_dump_body(const byte_t* stream, size_t size, stream_t* debugstream = nullptr);

    void clear();

    range_t _range;
    uint16 _extension_len;
    std::list<tls_extension*> _extensions;

   private:
    tls_hs_type_t _type;
    tls_session* _session;
    uint32 _len;
    bool _is_dtls;
    uint16 _dtls_seq;
    uint32 _fragment_offset;
    uint32 _fragment_len;
    size_t _hdrsize;

    t_shared_reference<tls_handshake> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
