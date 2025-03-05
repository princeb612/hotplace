/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_BASICSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_BASICSOCKET__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client socket
 */
class basic_socket {
   public:
    virtual ~basic_socket();

    virtual bool support_tls(); /* override */
    virtual int socket_type();  /* override */

    int addref();
    int release();

   protected:
    basic_socket();

   private:
    t_shared_reference<basic_socket> _shared;
    socket_t _fd;
};

}  // namespace net
}  // namespace hotplace

#endif
