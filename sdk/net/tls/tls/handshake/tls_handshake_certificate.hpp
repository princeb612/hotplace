/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECERTIFICATE__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECERTIFICATE__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * @remarks
 *          RFC 5246 7.4.2.  Server Certificate
 *          RFC 5246 7.4.6.  Client Certificate
 * @example
 *          tls_record_handshake record(session);
 *          auto handshake = new tls_handshake_certificate(session);
 *          handshake->set(from_server, certfile, keyfile);
 *
 *          record.get_handshakes().add(handshake);
 *          record.write(from_server, packet);
 */
class tls_handshake_certificate : public tls_handshake {
   public:
    tls_handshake_certificate(tls_session* session);

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
