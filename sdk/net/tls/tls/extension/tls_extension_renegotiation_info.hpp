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
    tls_extension_renegotiation_info(tls_session* session);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& bin);

   private:
    std::list<uint8> _modes;
};

}  // namespace net
}  // namespace hotplace

#endif
