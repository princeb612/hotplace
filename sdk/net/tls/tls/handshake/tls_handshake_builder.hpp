/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_HANDSHAKE_TLSHANDSHAKEBUILDER__
#define __HOTPLACE_SDK_NET_TLS_HANDSHAKE_TLSHANDSHAKEBUILDER__

#include <hotplace/sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

class tls_handshake_builder {
   public:
    tls_handshake_builder();

    tls_handshake_builder& set(tls_hs_type_t type);
    tls_handshake_builder& set(tls_session* session);
    tls_handshake* build();
    tls_handshake* build(tls_hs_type_t type, tls_session* session, std::function<return_t(tls_handshake*)> func = nullptr);

    tls_hs_type_t get_type();
    tls_session* get_session();

   private:
    tls_hs_type_t _type;
    tls_session* _session;
};

}  // namespace net
}  // namespace hotplace

#endif
