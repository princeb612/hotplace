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

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_TLSCLIENTSOCKET2__
#define __HOTPLACE_SDK_NET_BASIC_TLS_TLSCLIENTSOCKET2__

#include <sdk/net/basic/socket/async_client_socket.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client
 * @sample
 *          // sketch
 *          tls_client_socket2 cli;
 *          cli.set_minimum_version(tls_12);
 *          ret = cli.connect(addr, port, tmo);
 *          if (success == ret) {
 *              ret = cli.send(msg.c_str(), msg.size(), &cbsent);
 *              if (success == ret) {
 *                  cli.read(buf, bufsize, &cbread);
 *              }
 *          }
 */
class tls_client_socket2 : public async_client_socket {
   public:
    tls_client_socket2(tls_version_t minver = tls_12);

    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);

    tls_session& get_session();
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
