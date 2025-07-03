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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONALPN__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONALPN__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   application_layer_protocol_negotiation (ALPN, 0x0010)
 */
class tls_extension_alpn : public tls_extension {
   public:
    tls_extension_alpn(tls_handshake* handshake);

    const binary_t& get_protocols();
    void set_protocols(const binary_t& protocols);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    binary_t _protocols;
};

}  // namespace net
}  // namespace hotplace

#endif
