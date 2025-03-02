/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSRECORD_BUILDER__
#define __HOTPLACE_SDK_NET_TLS_TLSRECORD_BUILDER__

#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class tls_record_builder {
   public:
    tls_record_builder();

    tls_record_builder& set(tls_session* session);
    tls_record_builder& set(uint8 type);
    tls_record* build();

    tls_session* get_session();
    uint8 get_type();

   private:
    tls_session* _session;
    uint8 _type;
};

}  // namespace net
}  // namespace hotplace

#endif
