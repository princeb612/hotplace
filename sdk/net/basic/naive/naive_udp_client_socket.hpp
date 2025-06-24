/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVEUDPCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVEUDPCLIENTSOCKET__

#include <sdk/net/basic/client_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   UDP client socket
 * @sample
 *          auto cli = new naive_udp_client_socket;
 *          ret = cli->open(&addr, option.address.c_str(), option.port);
 *          if (errorcode_t::success == ret) {
 *              for (auto i = 0; i < option.count; i++) {
 *                  size_t cbsent = 0;
 *                  auto test = cli->sendto(option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&addr, addrlen);
 *                  if (errorcode_t::success == test) {
 *                      size_t cbread = 0;
 *                      test = cli->recvfrom(buffer, option.bufsize, &cbread, (sockaddr*)&addr, &addrlen);
 *                      if (errorcode_t::success == test) {
 *                          // do_something(buffer, cbread);
 *                      }
 *                  }
 *              }
 *              cli->close();
 *          }
 *          cli->release();
 */
class naive_udp_client_socket : public client_socket {
   public:
    naive_udp_client_socket();

    virtual return_t open(sockaddr_storage_t* sa, const char* address, uint16 port);
    virtual return_t close();

    virtual return_t recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    virtual return_t sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    virtual int socket_type();
    virtual socket_t get_socket();

   protected:
   private:
    socket_t _fd;
};

}  // namespace net
}  // namespace hotplace

#endif
