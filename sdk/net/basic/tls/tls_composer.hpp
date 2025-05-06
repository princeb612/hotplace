/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_TLSCOMPOSER__
#define __HOTPLACE_SDK_NET_BASIC_TLS_TLSCOMPOSER__

#include <sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

class tls_composer {
   public:
    tls_composer(tls_session* session);
    virtual ~tls_composer();

    return_t handshake(tls_direction_t dir, unsigned wto, std::function<void(binary_t&)> func);

    tls_session* get_session();
    void set_minver(tls_version_t version);
    void set_maxver(tls_version_t version);
    uint16 get_minver();
    uint16 get_maxver();

   protected:
    return_t do_client_hello(std::function<void(binary_t&)> func);
    return_t do_server_hello(std::function<void(binary_t&)> func);
    return_t do_client_handshake(tls_direction_t dir, unsigned wto, std::function<void(binary_t&)> func);
    return_t do_server_handshake(tls_direction_t dir, unsigned wto, std::function<void(binary_t&)> func);

    return_t do_compose(tls_record* record, tls_direction_t dir, std::function<void(binary_t&)> func);
    return_t do_compose(tls_records* records, tls_direction_t dir, std::function<void(binary_t&)> func);

    tls_session* _session;
    uint16 _minspec;
    uint16 _maxspec;
};

}  // namespace net
}  // namespace hotplace

#endif
