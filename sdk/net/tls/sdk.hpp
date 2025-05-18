/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_SDK__
#define __HOTPLACE_SDK_NET_TLS_SDK__

#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   certificate
 * @param   const char* certfile [in]
 * @param   const char* keyfile [in]
 * @param   const char* chainfile [in]
 * @example
 *          load_certificate("rsa.crt", "rsa.key", nullptr);
 *          load_certificate("ecdsa.crt", "ecdsa.key", nullptr);
 */
return_t load_certificate(const char* certfile, const char* keyfile, const char* chainfile);

}  // namespace net
}  // namespace hotplace

#endif
