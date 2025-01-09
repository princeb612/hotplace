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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_SUPPORTED_GROUPS__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_SUPPORTED_GROUPS__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   supported_groups (0x000a)
 */
class tls_extension_supported_groups : public tls_extension {
   public:
    tls_extension_supported_groups(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    tls_extension_supported_groups& add_group(uint16 group);
    const binary_t& get_supported_groups();

   protected:
   private:
    binary_t _supported_groups;
};

}  // namespace net
}  // namespace hotplace

#endif
