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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_ALPN__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_ALPN__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   application_layer_protocol_negotiation (ALPN, 0x0010)
 */
class tls_extension_alpn : public tls_extension {
   public:
    tls_extension_alpn(tls_session* session);

    const binary_t& get_protocols();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);

   private:
    binary_t _protocols;
};

}  // namespace net
}  // namespace hotplace

#endif
