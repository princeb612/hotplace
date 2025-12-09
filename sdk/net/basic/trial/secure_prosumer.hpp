/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_SECUREPROSUMER__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_SECUREPROSUMER__

#include <hotplace/sdk/base/system/semaphore.hpp>
#include <hotplace/sdk/net/basic/trial/types.hpp>
#include <hotplace/sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS
 * @sa      trial_tls_client_socket, trial_tls_server_socket
 */
class secure_prosumer {
   public:
    secure_prosumer();

    return_t produce(tls_session* session, tls_direction_t dir, std::function<void(basic_stream&, sockaddr_storage_t&)> func);
    return_t produce(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, struct sockaddr* addr = nullptr,
                     socklen_t* addrlen = nullptr);
    return_t consume(int sock_type, uint32 wto, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr = nullptr,
                     socklen_t* addrlen = nullptr);

   protected:
    return_t do_produce(tls_session* session, tls_direction_t dir, struct sockaddr* addr = nullptr, socklen_t* addrlen = nullptr);
    return_t do_produce(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, struct sockaddr* addr = nullptr,
                        socklen_t* addrlen = nullptr);

    critical_section _mlock;
    std::queue<socket_buffer_t> _mq;
    semaphore _msem;
    basic_stream _mbs;
};

}  // namespace net
}  // namespace hotplace

#endif
