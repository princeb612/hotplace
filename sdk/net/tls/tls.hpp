/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS__
#define __HOTPLACE_SDK_NET_TLS_TLS__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/net/types.hpp>
#include <hotplace/sdk/net/tls/x509.hpp>

namespace hotplace {
namespace net {

/*
 * @brief TLS
 * @sample
 *      transport_layer_security tls;
 *      uint32 ret = errorcode_t::success;
 *      int sock = socket (PF_INET, SOCK_STREAM, 0);
 *      struct sockaddr_in addr;
 *      addr.sin_family = AF_INET;
 *      addr.sin_port = htons (PORT);
 *      addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
 *      connect (sock, (struct sockaddr*)&addr, sizeof (addr));
 *      x509_t* x509 = nullptr;
 *      // snippet 1
 *      {
 *          SSL_CTX* sslctx = SSL_CTX_new (SSLv23_method ());
 *          // SSL_CTX_set_options (sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); // TLS 1.0 and above
 *          // SSL_CTX_set_cipher_list (sslctx, "DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:AES256-SHA256");
 *          try {
 *              x509 = new x509_t (sslctx);
 *          }
 *          catch (std::bad_alloc)
 *          {
 *              // ...
 *          }
 *      }
 *      // snippet 2
 *		{
 *          x509_create (&x509);
 *      }
 *      tls.attach (x509);
 *      ret = tls.connect (&tls_handle, sock, 10);
 *      if (errorcode_t::success == ret)
 *      {
 *          int size_sent = 0;
 *          tls.send (tls_handle, mode, message, strlen (message), 0, &size_sent);
 *      }
 *      tls.close (tls_handle); // close (sock)
 *      SSL_CTX_free (sslctx);
 *      close (sock);
 *      x509->release ();
 */
class transport_layer_security
{
public:
    transport_layer_security (SSL_CTX* x509);
    ~transport_layer_security ();

    /**
     * @brief   open
     * @param   tls_context_t** handle      [OUT]
     * @param   int             type        [IN]
     * @param   LPCSTR          addr        [IN]
     * @param   uint16          port        [IN]
     * @param   uint32          to_seconds  [IN] seconds
     * @remarks socket 생성 및 연결을 포함한 구현을 하는 경우
     */
    return_t connect (tls_context_t** handle, int type, const char* addr, uint16 port, uint32 to_seconds);
    /**
     * @brief   open
     * @param   tls_context_t** handle      [OUT]
     * @param   socket_t        sock        [IN]
     * @remarks 연결된 socket 으로 핸들만 구성하는 경우
     */
    return_t connect (tls_context_t** handle, socket_t sock, uint32 to_seconds = NET_DEFAULT_TIMEOUT);
    /**
     * @brief   socket layer handshake
     * @param   tls_context_t** handle      [OUT]
     * @param   socket_t        Sock        [IN] client socket
     * @remarks 연결된 소켓에 대해 handshake 를 진행한다.
     *
     *          client_socket = accept (...);                    // client socket
     *          ret = ssl->accept (&sslhandle, client_socket); // handshake
     */
    return_t accept (tls_context_t** handle, socket_t Sock);
    /**
     * @brief   close
     * @param   tls_context_t*  handle      [IN]
     * @remarks connect, accept 등으로 생성된 핸들을 해제한다.
     */
    return_t close (tls_context_t* handle);

    /*
     * @brief   read (network_Server_v2 specification)
     * @param   tls_context_t*  handle      [IN]
     * @param   int             mode        [IN] see tls_io_flag_t (2 recv 1 BIO_write 0 SSL_read)
     * @param   void*           buffer      [IN]
     * @param   size_t          buffer_size [IN]
     * @param   size_t*         size_read   [OUT]
     */
    return_t read (tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* size_read);

    /**
     * @brief   send
     * @param   tls_context_t*  handle      [IN]
     * @param   const char*     data        [IN]
     * @param   size_t          size_data   [IN]
     * @param   size_t*         size_sent   [OUT]
     * @remarks send 를 SSL_write 로 대체
     */
    return_t send (tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent);

    socket_t get_socket (tls_context_t* handle);

    int addref ();
    int release ();

    SSL_CTX* get ();

protected:
    SSL_CTX* _x509;
    t_shared_reference <transport_layer_security> _shared;
};

}
}  // namespace

#endif
