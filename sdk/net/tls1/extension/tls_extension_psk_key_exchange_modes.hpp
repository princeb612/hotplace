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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_PSK_KEY_EXCHANGE_MODES__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_PSK_KEY_EXCHANGE_MODES__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   psk_key_exchange_modes (0x002d)
 */
class tls_extension_psk_key_exchange_modes : public tls_extension {
   public:
    tls_extension_psk_key_exchange_modes(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    uint8 _modes;
    binary_t _mode;
};

}  // namespace net
}  // namespace hotplace

#endif
