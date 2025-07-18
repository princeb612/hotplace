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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONRENEGOTIATIONINFO__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONRENEGOTIATIONINFO__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   psk_key_exchange_modes (0x002d)
 */
class tls_extension_renegotiation_info : public tls_extension {
   public:
    tls_extension_renegotiation_info(tls_handshake* handshake);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
