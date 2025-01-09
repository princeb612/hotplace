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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_SNI__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_SNI__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   server_name (SNI, server name indicator, 0x0000)
 */
class tls_extension_sni : public tls_extension {
   public:
    tls_extension_sni(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    uint8 get_nametype();
    void set_hostname(const std::string& hostname);
    const binary_t& get_hostname();

   protected:
   private:
    uint8 _nametype;
    binary_t _hostname;
};

}  // namespace net
}  // namespace hotplace

#endif
