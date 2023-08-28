/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSCLIENT__
#define __HOTPLACE_SDK_NET_TLS_TLSCLIENT__

#include <hotplace/sdk/net/basic/client_socket.hpp>
#include <hotplace/sdk/net/tls/tls.hpp>
#include <hotplace/sdk/net/tls/x509.hpp>

namespace hotplace {
namespace net {

/**
 * @brief tls client
 * @example
 *  #if defined _WIN32 || defined _WIN64
 *      winsock_startup ();
 *  #endif
 *
 *      openssl_startup ();
 *      openssl_thread_setup ();
 *
 *      x509_t* cert_handle = nullptr;
 *      socket_t sock = 0;
 *      x509_create (&cert_handle, 0);
 *
 *      tls_context_t* handle = nullptr;
 *      transport_layer_security_client cli;
 *      cli.open (&cert, cert_handle);
 *      ret = cli.connect (&sock, &handle, option.host.c_str (), option.port, 3);
 *      if (errorcode_t::success == ret) {
 *          printf ("connected %d\n", sock);
 *          std::string request;
 *          request = "GET /";
 *
 *          size_t cbsent = 0;
 *          std::string body = format ("GET / HTTP/1.1\nContent-Length: 0\n\n");
 *          cli.send (sock, handle, body.c_str (), body.size(), &cbsent);
 *
 *          char buf [4];
 *          size_t sizeread = 0;
 *
 *          ret = cli.read (sock, handle, buf, sizeof (buf), &sizeread);
 *          printf ("status 0x%08x - %.*s\n", ret, (int)sizeread, buf);
 *          while (errorcode_t::more_data == ret) {
 *              ret = cli.more (sock, handle, buf, sizeof (buf), &sizeread);
 *              printf ("status 0x%08x - %.*s\n", ret, (int)sizeread, buf);
 *          }
 *
 *          cli.close (sock, handle);
 *      }
 *
 *      cert.close (cert_handle);
 *
 *      openssl_thread_cleanup ();
 *      openssl_cleanup ();
 *
 *  #if defined _WIN32 || defined _WIN64
 *      winsock_cleanup ();
 *  #endif
 */
class transport_layer_security_client : public client_socket
{
public:
    transport_layer_security_client (transport_layer_security* tls);
    virtual ~transport_layer_security_client ();

    /**
     * @brief   connect
     * @param   socket_t*       sock            [OUT]
     * @param   tls_context_t** tls_handle      [OUT]
     * @param   const char*     address         [IN]
     * @param   uint16          port            [IN]
     * @param   uint32          timeout         [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t connect (socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t close (socket_t sock, tls_context_t* tls_handle);
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @return  error code (see error.hpp)
     *          if return errorcode_t::more_data, call more member function
     *          ret = cli.read (sock, handle, buf, sizeof (buf), &sizeread);
     *          printf ("%.*s\n", (int) sizeread, buf);
     *          while (errorcode_t::more_data == ret) {
     *              ret = cli.more (sock, handle, buf, sizeof (buf), &sizeread);
     *              printf ("%.*s\n", (int) sizeread, buf);
     *          }
     */
    virtual return_t read (socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief read more
     * @param socket_t          sock
     * @param tls_context_t*    tls_handle
     * @param char*             ptr_data
     * @param size_t            size_data
     * @param size_t*           cbread
     * @return
     *      errorcode_t::pending   no data ready
     *      errorcode_t::more_data more data
     */
    virtual return_t more (socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send (socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    int addref ();
    int release ();

protected:
    transport_layer_security* _tls;
    t_shared_reference <transport_layer_security_client> _shared;
};

}
}  // namespace

#endif
