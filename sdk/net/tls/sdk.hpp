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

#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/tls/types.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

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

/**
 * @brief   keylog callback
 */
void set_tls_keylog_callback(std::function<void(const char*)> func);

return_t kindof_handshake(tls_handshake* handshake, protection_space_t& space);
bool is_kindof_handshake(tls_handshake* handshake, protection_space_t space);
return_t kindof_frame(quic_frame* frame, protection_space_t& space);
bool is_kindof_frame(quic_frame* frame, protection_space_t space);
return_t kindof_frame(quic_frame_t type, protection_space_t& space);
bool is_kindof_frame(quic_frame_t type, protection_space_t space);

}  // namespace net
}  // namespace hotplace

#endif
