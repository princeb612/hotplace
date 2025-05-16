/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SDK_TLSSERVERSOCKET2__
#define __HOTPLACE_SDK_NET_BASIC_SDK_TLSSERVERSOCKET2__

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/net/basic/naive/tcp_server_socket.hpp>  // tcp_server_socket
#include <sdk/net/basic/sdk/secure_prosumer.hpp>
#include <sdk/net/basic/sdk/types.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

class tls_server_socket2 : public tcp_server_socket {
   public:
    tls_server_socket2(tls_version_t version = tls_12);
    virtual ~tls_server_socket2();

    /**
     * @brief   tls accept
     * @param   socket_context_t** handle [out]
     * @param   socket_t cli_socket [in]
     */
    virtual return_t tls_accept(socket_context_t** handle, socket_t cli_socket);
    /**
     * @brief   tls_stop_accept
     */
    virtual return_t tls_stop_accept();
    /**
     * @brief   read
     * @param   socket_context_t* handle [in]
     * @param   int mode [in]
     * @param   char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbread [out]
     */
    virtual return_t read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_context_t* handle [in]
     * @param   const char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbsent [out]
     */
    virtual return_t send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    /**
     * @override
     * @return  return true
     */
    virtual bool support_tls();

    uint32 get_wto();
    secure_prosumer* get_secure_prosumer();

   protected:
   private:
    tls_version_t _version;

    secure_prosumer _secure;
};

}  // namespace net
}  // namespace hotplace

#endif
