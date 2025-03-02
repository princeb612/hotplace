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

#ifndef __HOTPLACE_SDK_NET_TLS_TLSEXTENSION_SNI__
#define __HOTPLACE_SDK_NET_TLS_TLSEXTENSION_SNI__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   server_name (SNI, server name indicator, 0x0000)
 */
class tls_extension_sni : public tls_extension {
   public:
    tls_extension_sni(tls_session* session);

    uint8 get_nametype();
    binary& get_hostname();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& bin);

   private:
    uint8 _nametype;
    binary _hostname;
};

}  // namespace net
}  // namespace hotplace

#endif
