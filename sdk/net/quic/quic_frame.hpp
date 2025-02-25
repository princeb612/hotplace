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

#ifndef __HOTPLACE_SDK_NET_QUIC_FRAME__
#define __HOTPLACE_SDK_NET_QUIC_FRAME__

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

class quic_frame {
    friend class quic_frame_builder;

   public:
    quic_frame(quic_frame_t type, tls_session* session);
    virtual ~quic_frame();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& bin);

    quic_frame_t get_type();
    tls_session* get_session();

    void addref();
    void release();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    void set_type(uint64 type);

    quic_frame_t _type;
    tls_session* _session;
    t_shared_reference<quic_frame> _shared;
};

class quic_frame_padding : public quic_frame {
   public:
    quic_frame_padding(tls_session* session);
    virtual ~quic_frame_padding();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

class quic_frame_ping : public quic_frame {
   public:
    quic_frame_ping(tls_session* session);
    virtual ~quic_frame_ping();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

class quic_frame_ack : public quic_frame {
   public:
    quic_frame_ack(tls_session* session);
    virtual ~quic_frame_ack();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

class quic_frame_reset_stream : public quic_frame {
   public:
    quic_frame_reset_stream(tls_session* session);
    virtual ~quic_frame_reset_stream();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

class quic_frame_stop_sending : public quic_frame {
   public:
    quic_frame_stop_sending(tls_session* session);
    virtual ~quic_frame_stop_sending();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

class quic_frame_crypto : public quic_frame {
   public:
    quic_frame_crypto(tls_session* session);
    virtual ~quic_frame_crypto();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

class quic_frame_new_token : public quic_frame {
   public:
    quic_frame_new_token(tls_session* session);
    virtual ~quic_frame_new_token();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

/**
 * @brief   read
 * @param   tls_session* session [in]
 * @param   const byte_t** stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 */
return_t quic_dump_frame(tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir = from_server);
return_t quic_dump_frame(tls_session* session, const binary_t frame, size_t& pos, tls_direction_t dir = from_server);

}  // namespace net
}  // namespace hotplace

#endif
