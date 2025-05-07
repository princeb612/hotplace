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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONBUILDER__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONBUILDER__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

class tls_extension_builder {
   public:
    tls_extension_builder();
    tls_extension_builder& set(tls_session* session);
    tls_extension_builder& set(uint16 type);
    tls_extension_builder& set(tls_direction_t dir);
    tls_extension_builder& set(tls_hs_type_t hs);
    tls_extension* build();

    tls_session* get_session();
    uint16 get_type();
    tls_direction_t get_direction();
    tls_hs_type_t get_handshake_type();

   private:
    tls_session* _session;
    uint16 _type;
    tls_direction_t _dir;
    tls_hs_type_t _hs;
};

}  // namespace net
}  // namespace hotplace

#endif
