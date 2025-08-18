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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAME__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAME__

#include <sdk/base/nostd/ovl.hpp>
#include <sdk/base/stream/segmentation.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_frame {
    friend class quic_frame_builder;

   public:
    quic_frame(quic_frame_t type, quic_packet* packet);
    virtual ~quic_frame();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& bin);

    quic_frame_t get_type();
    quic_packet* get_packet();

    void addref();
    void release();

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    void set_type(uint64 type);

    quic_frame_t _type;
    quic_packet* _packet;
    t_shared_reference<quic_frame> _shared;
};

/**
 * @brief   read
 * @param   quic_packet* packet [in]
 * @param   const byte_t** stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 */
return_t quic_dump_frame(quic_packet* packet, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir = from_server);
return_t quic_dump_frame(quic_packet* packet, const binary_t frame, size_t& pos, tls_direction_t dir = from_server);

}  // namespace net
}  // namespace hotplace

#endif
