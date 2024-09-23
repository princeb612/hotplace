/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS__
#define __HOTPLACE_SDK_NET_TLS_TLS__

#include <sdk/crypto.hpp>
#include <sdk/net/tls/x509cert.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief TLS
 * @example
 *      uint32 ret = errorcode_t::success;
 *      x509cert_open_simple(x509cert_flag_tls, &sslctx);
 *      transport_layer_security tls(sslctx);
 *      tls_client_socket cli(&tls);
 *      cli.connect(&sock, &tlshandle, host, port, 1);
 *      cli.send(sock, tlshandle, message, size, &cbsent);
 *      size_t cbread = 0;
 *      ret_read = cli.read(sock, tlshandle, buffer, BUFFER_SIZE, &cbread);
 *      bs.write(buffer, cbread);
 *      while (errorcode_t::more_data == ret_read) {
 *          ret_read = cli.more(sock, tlshandle, buffer, BUFFER_SIZE, &cbread);
 *          bs.write(buffer, cbread);
 *      }
 *      cli.close(sock, tlshandle);
 *      SSL_CTX_free(sslctx);
 */
class transport_layer_security {
   public:
    transport_layer_security(SSL_CTX* sslctx);
    transport_layer_security(x509cert* cert);
    ~transport_layer_security();

    /**
     * @brief   connect
     * @param   tls_context_t** handle      [OUT]
     * @param   int             type        [IN]
     * @param   LPCSTR          addr        [IN]
     * @param   uint16          port        [IN]
     * @param   uint32          to_seconds  [IN] seconds
     * @remarks socket 생성 및 연결을 포함한 구현을 하는 경우
     */
    return_t connect(tls_context_t** handle, int type, const char* addr, uint16 port, uint32 to_seconds);
    /**
     * @brief   connect to
     * @param   tls_context_t** handle      [OUT]
     * @param   socket_t        sock        [IN]
     * @param   const char*     address     [in]
     * @param   uint16          port        [in]
     * @remarks 연결된 socket 으로 핸들만 구성하는 경우
     */
    return_t connectto(tls_context_t** handle, socket_t sock, const char* address, uint16 port, uint32 to_seconds = NET_DEFAULT_TIMEOUT);
    /**
     * @brief   connect to
     * @param   tls_context_t** handle      [OUT]
     * @param   socket_t        sock        [IN]
     * @param   const sockaddr* addr        [in]
     * @param   socklen_t       addrlen     [in]
     */
    return_t connectto(tls_context_t** handle, socket_t sock, const sockaddr* addr, socklen_t addrlen, uint32 to_seconds = NET_DEFAULT_TIMEOUT);
    /**
     * @brief   socket layer handshake
     * @param   tls_context_t** handle      [OUT]
     * @param   socket_t        clisock     [IN] socket
     * @remarks 연결된 소켓에 대해 handshake 를 진행한다.
     *
     *          cli_socket = accept (...);
     *          ret = ssl->accept (handle, cli_socket); // handshake
     */
    return_t accept(tls_context_t** handle, socket_t sock);
    /**
     * @brief   DTLS
     */
    return_t dtls_open(tls_context_t** handle, socket_t sock);
    /**
     * @brief   handshake
     * @param   tls_context_t* handle [in]
     * @param   sockaddr* addr [inopt]
     * @param   socklen_t addrlen [in]
     * @remarks
     *
     *          // handshake with cookie
     *          SSL_CTX_set_cookie_generate_cb(sslctx, set_cookie_generate_callback_routine);
     *          SSL_CTX_set_cookie_verify_cb(sslctx, set_cookie_verify_callback_routine);
     *          BIO_ADDR* bio_addr = BIO_ADDR_new();
     *          DTLSv1_listen(ssl, bio_addr);
     *          BIO_ADDR_free(bio_addr);
     *
     *          // cf. handshake without cookie
     *			SSL_set_accept_state(ssl);
     *			SSL_do_handshake(ssl);
     *
     */
    return_t dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   close
     * @param   tls_context_t*  handle      [IN]
     * @remarks connect, accept 등으로 생성된 핸들을 해제한다.
     */
    return_t close(tls_context_t* handle);

    /**
     * @brief   read (network_Server_v2 specification)
     * @param   tls_context_t*  handle      [IN]
     * @param   int             mode        [IN] see tls_io_flag_t (2 recv 1 BIO_write 0 SSL_read)
     * @param   void*           buffer      [IN]
     * @param   size_t          buffer_size [IN]
     * @param   size_t*         size_read   [OUT]
     */
    return_t read(tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* size_read);
    return_t recvfrom(tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* size_read, struct sockaddr* addr, socklen_t* addrlen);

    /**
     * @brief   send
     * @param   tls_context_t*  handle      [IN]
     * @param   const char*     data        [IN]
     * @param   size_t          size_data   [IN]
     * @param   size_t*         size_sent   [OUT]
     * @remarks send 를 SSL_write 로 대체
     */
    return_t send(tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent);
    return_t sendto(tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent, const struct sockaddr* addr, socklen_t addrlen);

    socket_t get_socket(tls_context_t* handle);

    int addref();
    int release();

    SSL_CTX* get();

   protected:
    /**
     * @brief   SSL_connect
     * @param   socket_t    sock        [in]
     * @param   SSL*        ssl         [in]
     * @param   uint32      dwSeconds   [in]
     * @param   uint32      nbio        [in]
     */
    return_t do_connect(socket_t sock, SSL* ssl, uint32 dwSeconds, uint32 nbio);
    /**
     * @brief   dtls_handshake
     */
    return_t do_dtls_listen(tls_context_t* handle, sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   SSL_accept
     */
    return_t do_accept(tls_context_t* handle);

    SSL_CTX* _ctx;
    t_shared_reference<transport_layer_security> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
