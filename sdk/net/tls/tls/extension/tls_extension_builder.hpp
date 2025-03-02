/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSEXTENSION_BUILDER__
#define __HOTPLACE_SDK_NET_TLS_TLSEXTENSION_BUILDER__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

class tls_extension_builder {
   public:
    tls_extension_builder();
    tls_extension_builder& set(tls_session* session);
    tls_extension_builder& set(uint16 type);
    tls_extension_builder& set(tls_hs_type_t handshake);
    tls_extension* build();

    tls_session* get_session();
    tls_hs_type_t get_handshake();

   private:
    tls_session* _session;
    uint16 _type;
    tls_hs_type_t _handshake;
};

}  // namespace net
}  // namespace hotplace

#endif
