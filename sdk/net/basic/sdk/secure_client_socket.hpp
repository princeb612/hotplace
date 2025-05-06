/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      insecure simple implementation to understand TLS
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SDK_SECURECLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_SDK_SECURECLIENTSOCKET__

#include <sdk/net/basic/sdk/async_client_socket.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client
 * @sample
 */
class secure_client_socket : public async_client_socket {
   public:
    tls_session* get_session();
    tls_version_t get_version();
    virtual bool support_tls();

   protected:
    secure_client_socket(tls_version_t version = tls_12);

    virtual return_t do_handshake();
    virtual return_t do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    virtual return_t do_secure();
    virtual return_t do_shutdown();
    virtual return_t do_send(binary_t& bin);

    tls_session _session;
    tls_version_t _version;

    critical_section _mlock;
    std::queue<bufferqueue_item_t> _mq;
    semaphore _msem;
    basic_stream _mbs;
};

}  // namespace net
}  // namespace hotplace

#endif
