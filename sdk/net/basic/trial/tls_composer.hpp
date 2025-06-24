/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TLSCOMPOSER__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TLSCOMPOSER__

#include <sdk/net/basic/trial/client_socket_prosumer.hpp>
#include <sdk/net/basic/trial/types.hpp>
#include <sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS
 * @sa      trial_tls_client_socket, trial_tls_server_socket
 */
class tls_composer {
   public:
    tls_composer(tls_session* session);
    virtual ~tls_composer();

    // from_client
    return_t handshake(tls_direction_t dir, unsigned wto, std::function<void(tls_session*, binary_t&)> func);
    // from_server
    return_t session_status_changed(uint32 session_status, tls_direction_t dir, uint32 wto, std::function<void(tls_session*, binary_t&)> func);

    tls_session* get_session();
    void set_minver(tls_version_t version);
    void set_maxver(tls_version_t version);
    uint16 get_minver();
    uint16 get_maxver();

   protected:
    return_t do_client_hello(std::function<void(tls_session*, binary_t&)> func);
    return_t do_client_handshake(tls_direction_t dir, unsigned wto, std::function<void(tls_session*, binary_t&)> func);
    return_t do_server_handshake_phase1(std::function<void(tls_session*, binary_t&)> func);
    return_t do_server_handshake_phase2(std::function<void(tls_session*, binary_t&)> func);

    return_t do_compose(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);
    return_t do_compose(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func);

    tls_session* _session;
    uint16 _minspec;
    uint16 _maxspec;
};

}  // namespace net
}  // namespace hotplace

#endif
