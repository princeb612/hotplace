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
 * @brief   BIO_ADDR*
 */
return_t BIO_ADDR_to_sockaddr(BIO_ADDR* bio_addr, struct sockaddr* sockaddr, socklen_t addrlen);
/**
 * @brief   BIO_ADDR*
 * @remarks BIO_dgram_get_peer(ssl)
 */
return_t SSL_dgram_peer_sockaddr(SSL* ssl, struct sockaddr* sockaddr, socklen_t addrlen);

/**
 * @brief   dtls cookie
 * @remarks hmac("sha256", app_instance_nonce, (sockaddr*)&address, sizeof(address));
 */
return_t generate_cookie_sockaddr(binary_t& cookie, const sockaddr* addr, socklen_t addrlen);
return_t dtls_cookie_dgram_peer_sockaddr(binary_t& cookie, SSL* ssl);

}  // namespace net
}  // namespace hotplace

#endif
