/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_TLS_TLSCLIENTSOCKET__

#include <sdk/net/basic/tcp_client_socket.hpp>
#include <sdk/net/tls/tls.hpp>
#include <sdk/net/tls/x509.hpp>

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
 *      socket_t sock = 0;
 *
 *      tls_context_t* handle = nullptr;
 *      SSL_CTX* x509 = nullptr;
 *      x509_open_simple(&x509);
 *      transport_layer_security tls(x509);
 *      tls_client_socket cli(&tls);
 *
 *      ret = cli.connect(&sock, &handle, url_info.host.c_str(), url_info.port, 3);
 *      if (errorcode_t::success == ret) {
 *          printf("connected %d\n", sock);
 *
 *          http_request req;
 *          req.open(format("GET %s HTTP/1.1", url_info.uri.c_str()));
 *          basic_stream body;
 *          req.get_request(body);
 *
 *          size_t cbsent = 0;
 *          ret = cli.send(sock, handle, body.c_str(), body.size(), &cbsent);
 *          printf("sent %zi\n", cbsent);
 *
 *          if (errorcode_t::success == ret) {
 *              char buf[4];
 *              size_t sizeread = 0;
 *
 *              network_protocol_group group;
 *              http_protocol http;
 *              network_stream stream_read; // fragmented
 *              network_stream stream_interpreted; // prototol interpreted
 *              group.add(&http);
 *
 *              ret = cli.read(sock, handle, buf, sizeof(buf), &sizeread);
 *              stream_read.produce(buf, sizeread);
 *              while (errorcode_t::more_data == ret) {
 *                  ret = cli.more(sock, handle, buf, sizeof(buf), &sizeread);
 *                  stream_read.produce(buf, sizeread);
 *              }
 *
 *              stream_read.write(&group, &stream_interpreted);
 *              network_stream_data* data = nullptr;
 *              stream_interpreted.consume(&data);
 *              if(data) {
 *                  printf("recv %zi\n", data->size());
 *
 *                  basic_stream bs;
 *                  dump_memory((byte_t*)data->content(), data->size(), &bs);
 *                  printf("%s\n", bs.c_str());
 *                  data->release();
 *              }
 *          }
 *
 *          cli.close(sock, handle);
 *      }
 *
 *      SSL_CTX_free(x509);
 *
 *      openssl_thread_cleanup ();
 *      openssl_cleanup ();
 *
 *  #if defined _WIN32 || defined _WIN64
 *      winsock_cleanup ();
 *  #endif
 */
class tls_client_socket : public tcp_client_socket {
   public:
    tls_client_socket(transport_layer_security* tls);
    virtual ~tls_client_socket();

    /**
     * @brief   connect
     * @param   socket_t*       sock            [OUT]
     * @param   tls_context_t** tls_handle      [OUT]
     * @param   const char*     address         [IN]
     * @param   uint16          port            [IN]
     * @param   uint32          timeout         [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle);
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
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
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
    virtual return_t more(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    virtual bool support_tls();

    int addref();
    int release();

   protected:
    transport_layer_security* _tls;
    t_shared_reference<tls_client_socket> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
