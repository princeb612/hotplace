/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_certificate_request.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECERTIFICATEREQUEST__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECERTIFICATEREQUEST__

#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class HOTPLACE_NET_API tls_handshake_certificate_request : public tls_handshake {
   public:
    tls_handshake_certificate_request(tls_session* session);
    virtual ~tls_handshake_certificate_request();

    const binary_t& get_request_context() const;
    void set_request_context(const binary_t& context);

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    binary_t _request_context;
};

}  // namespace net
}  // namespace hotplace

#endif
