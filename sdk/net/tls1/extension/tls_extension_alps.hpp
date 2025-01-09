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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_ALPS__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_ALPS__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   application_layer_protocol_settings (ALPS, 0x4469)
 */
class tls_extension_alps : public tls_extension {
   public:
    tls_extension_alps(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    const binary_t& get_alpn();

   protected:
   private:
    uint16 _alps_len;
    binary_t _alpn;
};

}  // namespace net
}  // namespace hotplace

#endif
