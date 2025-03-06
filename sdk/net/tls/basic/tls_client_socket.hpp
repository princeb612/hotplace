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

#ifndef __HOTPLACE_SDK_NET_TLS_BASIC_TLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_TLS_BASIC_TLSCLIENTSOCKET__

#include <sdk/net/basic/socket/tcp_client_socket.hpp>
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
class tls_client_socket2 : public tcp_client_socket {
   public:
    tls_client_socket2(tls_version_t minver = tls_13);

    virtual return_t connect(const char* address, uint16 port, uint32 timeout);
    virtual return_t close();

    virtual return_t read(char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t more(char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);

   protected:
    return_t do_handshake();
    return_t do_client_hello(binary_t& bin);

   private:
    tls_session _session;
    tls_version_t _minver;
};

}  // namespace net
}  // namespace hotplace

#endif
