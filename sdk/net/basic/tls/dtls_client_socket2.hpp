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

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_DTLSCLIENTSOCKET2__
#define __HOTPLACE_SDK_NET_BASIC_TLS_DTLSCLIENTSOCKET2__

#include <sdk/net/basic/socket/async_client_socket.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client
 * @sample
 *          // sketch
 *          dtls_client_socket2 cli;
 *          cli.set_minimum_version(dtls_12);
 *          ret = cli.open(&addr, addr, port)
 *          if (success == ret) {
 *              ret = cli.sendto(msg.c_str(), msg.size(), &cbsent, , (sockaddr*)&addr, sizeof(addr));
 *              if (success == ret) {
 *                  cli.recvfrom(buf, bufsize, &cbread, (sockaddr*)&addr, &addrlen);
 *              }
 *          }
 */
class dtls_client_socket2 : public async_client_socket {
   public:
    dtls_client_socket2(tls_version_t version = dtls_12);

    virtual return_t sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    virtual bool support_tls();
    virtual int socket_type();

   protected:
    virtual return_t do_handshake();
    virtual return_t do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    virtual return_t do_secure();
    virtual return_t do_shutdown();

   private:
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
