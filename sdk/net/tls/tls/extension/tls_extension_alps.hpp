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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONALPS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONALPS__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   application_layer_protocol_settings (ALPS, 0x4469)
 */
class tls_extension_alps : public tls_extension {
   public:
    tls_extension_alps(tls_handshake* handshake);

    const binary_t& get_alpn();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint16 _alps_len;
    binary_t _alpn;
};

}  // namespace net
}  // namespace hotplace

#endif
