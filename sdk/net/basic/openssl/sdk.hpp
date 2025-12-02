/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_OPENSSL_SDK__
#define __HOTPLACE_SDK_NET_BASIC_OPENSSL_SDK__

#include <hotplace/sdk/net/types.hpp>

namespace hotplace {
namespace net {

return_t dtls_cookie_dgram_peer_sockaddr(binary_t& cookie, SSL* ssl);

/**
 * @brief   BIO_ADDR*
 */
return_t BIO_ADDR_to_sockaddr(BIO_ADDR* bio_addr, struct sockaddr* sockaddr, socklen_t addrlen);
/**
 * @brief   BIO_ADDR*
 * @remarks BIO_dgram_get_peer(ssl)
 */
return_t SSL_dgram_peer_sockaddr(SSL* ssl, struct sockaddr* sockaddr, socklen_t addrlen);

}  // namespace net
}  // namespace hotplace

#endif
