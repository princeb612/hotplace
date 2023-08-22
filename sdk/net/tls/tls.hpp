/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_SDK__
#define __HOTPLACE_SDK_NET_TLS_SDK__

#include <hotplace/sdk/net/types.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace net {

/*
 * @brief   SSL_connect
 * @param   socket_t    sock        [in]
 * @param   void*       ssl         [in] SSL*
 * @param   uint32      dwSeconds   [in]
 * @param   uint32      nbio        [in]
 */
return_t tls_connect (socket_t sock, void* ssl, uint32 dwSeconds, uint32 nbio);

}
}  // namespace

#endif
