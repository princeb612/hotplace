/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKEHELLOVERIFYREQUEST__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKEHELLOVERIFYREQUEST__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_hello_verify_request : public tls_handshake {
   public:
    tls_handshake_hello_verify_request(tls_session* session);
    virtual ~tls_handshake_hello_verify_request();

    void set_cookie(const binary_t& cookie);
    void set_cookie(binary_t&& cookie);
    const binary_t& get_cookie();

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    binary_t _cookie;
};

}  // namespace net
}  // namespace hotplace

#endif
