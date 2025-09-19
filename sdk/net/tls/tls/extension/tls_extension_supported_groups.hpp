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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSUPPORTEDGROUPS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSUPPORTEDGROUPS__

#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   supported_groups (0x000a)
 */
class tls_extension_supported_groups : public tls_extension {
   public:
    tls_extension_supported_groups(tls_handshake* handshake);
    virtual ~tls_extension_supported_groups();

    tls_extension_supported_groups& add(uint16 code);
    tls_extension_supported_groups& add(const std::string& name);

    size_t numberof_groups();
    void clear();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    std::list<uint16> _supported_groups;
};

}  // namespace net
}  // namespace hotplace

#endif
