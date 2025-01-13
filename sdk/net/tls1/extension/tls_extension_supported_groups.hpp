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

    tls_extension_supported_groups& add(uint16 code);
    tls_extension_supported_groups& add(const std::string& name);

    void clear();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);

   private:
    std::list<uint16> _supported_groups;
};

}  // namespace net
}  // namespace hotplace

#endif
