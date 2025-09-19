/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKE__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extensions.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

class tls_handshake {
    friend class dtls_record_publisher;
    friend class tls_handshakes;

   public:
    tls_handshake(tls_hs_type_t type, tls_session *session);
    virtual ~tls_handshake();

    static tls_handshake *read(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t &pos);

    virtual return_t read(tls_direction_t dir, const byte_t *stream, size_t size, size_t &pos);
    virtual return_t write(tls_direction_t dir, binary_t &bin);
    virtual void run_scheduled(tls_direction_t dir);

    void addref();
    void release();

    tls_extensions &get_extensions();

    tls_hs_type_t get_type();
    tls_session *get_session();
    size_t get_size();
    const range_t &get_header_range();
    size_t offsetof_header();
    size_t offsetof_body();
    uint32 get_body_size();

    return_t prepare_fragment(const byte_t *stream, uint32 size, uint16 seq, uint32 fragment_offset, uint32 fragment_length);
    void set_dtls_seq(uint16 seq);
    uint16 get_dtls_seq();
    uint32 get_fragment_offset();
    uint32 get_fragment_len();

    void set_flags(uint32 flags);
    uint32 get_flags();

   protected:
    /**
     * check message flow
     * @remarks
     *          RFC 8446 4.  Handshake Protocol
     *            Protocol messages MUST be sent in the order
     *            A peer which receives a handshake message in an unexpected order MUST abort the handshake with an "unexpected_message" alert.
     */
    virtual return_t do_preprocess(tls_direction_t dir);
    /**
     * update transcript hash, key calcuration, ...
     */
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t *stream, size_t size);
    /**
     * read header
     */
    virtual return_t do_read_header(tls_direction_t dir, const byte_t *stream, size_t size, size_t &pos);
    /**
     * read body
     */
    virtual return_t do_read_body(tls_direction_t dir, const byte_t *stream, size_t size, size_t &pos);
    /**
     * write header
     */
    virtual return_t do_write_header(tls_direction_t dir, binary_t &bin, const binary_t &body);
    /**
     * write body
     */
    virtual return_t do_write_body(tls_direction_t dir, binary_t &bin);

    void set_extension_len(uint16 len);

   private:
    range_t _range;
    uint16 _extension_len;
    tls_extensions _extensions;

    tls_hs_type_t _type;
    tls_session *_session;
    uint32 _bodysize;
    bool _is_dtls;
    uint16 _dtls_seq;
    uint32 _fragment_offset;
    uint32 _fragment_len;
    uint32 _reassembled_size;
    size_t _size;
    uint32 _flags;

    t_shared_reference<tls_handshake> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
