/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_SDK__
#define __HOTPLACE_SDK_NET_TLS_SDK__

#include <sdk/crypto.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   SSL_connect
 * @param   socket_t    sock        [in]
 * @param   SSL*        ssl         [in]
 * @param   uint32      dwSeconds   [in]
 * @param   uint32      nbio        [in]
 */
return_t tls_connect(socket_t sock, SSL* ssl, uint32 dwSeconds, uint32 nbio);

/**
 * @brief   BIO_ADDR*
 */
return_t BIO_ADDR_to_sockaddr(BIO_ADDR* bio_addr, struct sockaddr* sockaddr, socklen_t addrlen);
/**
 * @brief   BIO_ADDR*
 * @remarks BIO_dgram_get_peer(ssl)
 */
return_t SSL_to_sockaddr(SSL* ssl, struct sockaddr* sockaddr, socklen_t addrlen);

}  // namespace net
}  // namespace hotplace

#endif
