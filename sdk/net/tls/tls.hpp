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

enum tls_flag_t {
    closesocket_ondestroy = (1 << 0),
    tls_nbio = (1 << 1),
};

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
     * @brief   TLS
     * @param   tls_context_t** handle  [out]
     * @param   socket_t        sock    [in]
     * @param   uint32          flags   [inopt] see tls_flag_t
     * @return  error code (see error.hpp)
     */
    return_t tls_open(tls_context_t** handle, socket_t sock, uint32 flags = 0);
    /**
     * @brief   DTLS
     * @param   tls_context_t** handle  [out]
     * @param   socket_t        sock    [in]
     * @param   uint32          flags   [inopt] see tls_flag_t
     * @return  error code (see error.hpp)
     */
    return_t dtls_open(tls_context_t** handle, socket_t sock, uint32 flags = 0);
    /**
     * @brief   close
     * @param   tls_context_t*  handle  [in]
     * @return  error code (see error.hpp)
     */
    return_t close(tls_context_t* handle);

    /**
     * @brief   connect
     * @param   tls_context_t** handle      [out]
     * @param   int             type        [in]
     * @param   const char*     addr        [in]
     * @param   uint16          port        [in]
     * @param   uint32          wtoseconds  [inopt] seconds
     * @return  error code (see error.hpp)
     * @remarks set closesocket_ondestroy flag
     */
    return_t connect(tls_context_t** handle, int type, const char* addr, uint16 port, uint32 wtoseconds = NET_DEFAULT_TIMEOUT);
    /**
     * @brief   connect to
     * @param   tls_context_t** handle      [out]
     * @param   socket_t        sock        [in]
     * @param   const char*     address     [in]
     * @param   uint16          port        [in]
     * @param   uint32          wtoseconds  [inopt] seconds
     * @return  error code (see error.hpp)
     * @remarks do not set closesocket_ondestroy flag
     */
    return_t connectto(tls_context_t** handle, socket_t sock, const char* address, uint16 port, uint32 wtoseconds = NET_DEFAULT_TIMEOUT);
    /**
     * @brief   connect to
     * @param   tls_context_t** handle      [out]
     * @param   socket_t        sock        [in]
     * @param   const sockaddr* addr        [in]
     * @param   socklen_t       addrlen     [in]
     * @param   uint32          wtoseconds  [inopt] seconds
     * @return  error code (see error.hpp)
     * @remarks do not set closesocket_ondestroy flag
     */
    return_t connectto(tls_context_t** handle, socket_t sock, const sockaddr* addr, socklen_t addrlen, uint32 wtoseconds = NET_DEFAULT_TIMEOUT);
    /**
     * @brief   tls accept (handshake)
     * @param   tls_context_t** handle      [out]
     * @param   socket_t        clisock     [in] socket
     * @return  error code (see error.hpp)
     * @remarks 연결된 소켓에 대해 handshake 를 진행한다.
     *
     *          cli_socket = accept (...);
     *          // RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
     *          // RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
     *          // RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1
     *          ret = ssl->tls_handshake (handle, cli_socket); // handshake
     */
    return_t tls_handshake(tls_context_t** handle, socket_t sock);
    /**
     * @brief   dtls accept (handshake)
     * @param   tls_context_t* handle [in]
     * @param   sockaddr* addr [inopt]
     * @param   socklen_t addrlen [in]
     * @return  error code (see error.hpp)
     * @remarks
     *
     *          // RFC 9147 The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
     *          // RFC 6347 Datagram Transport Layer Security Version 1.2
     *          // RFC 4347 Datagram Transport Layer Security
     *
     *          // handshake with cookie
     *          SSL_CTX_set_cookie_generate_cb(sslctx, set_cookie_generate_callback_routine);
     *          SSL_CTX_set_cookie_verify_cb(sslctx, set_cookie_verify_callback_routine);
     *          BIO_ADDR* bio_addr = BIO_ADDR_new();
     *          DTLSv1_listen(ssl, bio_addr);
     *          BIO_ADDR_free(bio_addr);
     *
     *          // cf. without SSL_CTX_set_cookie_generate_cb, SSL_CTX_set_cookie_verify_cb
     *			SSL_set_accept_state(ssl);
     *			SSL_do_handshake(ssl);
     *
     */
    return_t dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen);

    /**
     * @brief   SSL_set_bio
     * @param   tls_context_t*  handle  [in]
     * @param   int             type    [in] 0 BIO_s_mem, 1 BIO_s_datagram
     * @return  error code (see error.hpp)
     */
    return_t set_tls_io(tls_context_t* handle, int type);

    /**
     * @brief   read (network_Server_v2 specification)
     * @param   tls_context_t*  handle      [in]
     * @param   int             mode        [in] see tls_io_flag_t (2 recv 1 BIO_write 0 SSL_read)
     * @param   void*           buffer      [in]
     * @param   size_t          buffer_size [in]
     * @param   size_t*         size_read   [out]
     * @return  error code (see error.hpp)
     */
    return_t read(tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* size_read);
    /**
     * @brief   recvfrom
     * @param   tls_context_t*      handle [in]
     * @param   int                 mode [in]
     * @param   void*               buffer [in]
     * @param   size_t              buffer_size [in]
     * @param   size_t*             size_read [out]
     * @param   struct sockaddr*    addr [out]
     * @param   socklen_t*          addrlen [in]
     * @return  error code (see error.hpp)
     */
    return_t recvfrom(tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* size_read, struct sockaddr* addr, socklen_t* addrlen);

    /**
     * @brief   send
     * @param   tls_context_t*  handle      [in]
     * @param   const char*     data        [in]
     * @param   size_t          size_data   [in]
     * @param   size_t*         size_sent   [out]
     * @return  error code (see error.hpp)
     */
    return_t send(tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent);
    /**
     * @brief   sendto
     * @param   tls_context_t*          handle      [in]
     * @param   int                     mode        [in]
     * @param   const char*             data        [in]
     * @param   size_t                  size_data   [in]
     * @param   size_t*                 size_sent   [out]
     * @param   const struct sockaddr*  addr        [in]
     * @param   socklen_t               addrlen     [in]
     * @return  error code (see error.hpp)
     */
    return_t sendto(tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent, const struct sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   socket related
     * @param   tls_context_t*  handle  [in]
     */
    socket_t get_socket(tls_context_t* handle);

    int addref();
    int release();

    SSL_CTX* get();

   protected:
    /**
     * @brief   SSL_connect
     * @param   tls_context_t*  handle  [in]
     * @param   uint32          wto     [in]
     * @return  error code (see error.hpp)
     */
    return_t do_connect(tls_context_t* handle, uint32 wto);
    /**
     * @brief   dtls_handshake
     * @param   tls_context_t*  handle  [in]
     * @param   sockaddr*       addr    [out]
     * @param   socklen_t       addrlen [in]
     * @return  error code (see error.hpp)
     */
    return_t do_dtls_listen(tls_context_t* handle, sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   SSL_accept
     * @param   tls_context_t*  handle  [in]
     * @return  error code (see error.hpp)
     */
    return_t do_accept(tls_context_t* handle);

    SSL_CTX* _ctx;
    t_shared_reference<transport_layer_security> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
