/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVETCPCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVETCPCLIENTSOCKET__

#include <hotplace/sdk/net/basic/client_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TCP client socket
 * @sample
 *          auto cli = new naive_tcp_client_socket;
 *          ret = cli->connect(option.address.c_str(), option.port, 1);
 *          if (errorcode_t::success == test) {
 *              size_t cbsent = 0;
 *              auto test = cli->send(option.message.c_str(), option.message.size(), &cbsent);
 *              if (errorcode_t::success == test) {
 *                  size_t cbread = 0;
 *                  test = cli->read(buffer, option.bufsize, &cbread);
 *                  if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
 *                      // do_something(buffer, cbread);
 *                      while (errorcode_t::more_data == test) {
 *                          test = cli->more(buffer, option.bufsize, &cbread);
 *                          if (errorcode_t::more_data == test) {
 *                              // do_something(buffer, cbread);
 *                          }
 *                      }
 *                  }
 *              }
 *              cli->close();
 *          }
 *          cli->release();
 */
class naive_tcp_client_socket : public client_socket {
   public:
    naive_tcp_client_socket();
    virtual ~naive_tcp_client_socket();

    /**
     * connect
     * IP4, IP6
     */
    virtual return_t connect(const char* address, uint16 port, uint32 timeout);
    /**
     * close
     */
    virtual return_t close();

    virtual return_t read(char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t more(char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);

    virtual int socket_type();
    virtual socket_t get_socket();

    virtual uint32 get_scheme();

   protected:
   private:
    socket_t _fd;
};

}  // namespace net
}  // namespace hotplace

#endif
