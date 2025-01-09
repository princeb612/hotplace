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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_EC_POINT_FORMATS__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_EC_POINT_FORMATS__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   ec_point_formats (0x000b)
 */
class tls_extension_ec_point_formats : public tls_extension {
   public:
    tls_extension_ec_point_formats(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    tls_extension_ec_point_formats& add_format(uint8 fmt);
    const binary_t& get_formats();

   protected:
   private:
    binary_t _formats;
};

}  // namespace net
}  // namespace hotplace

#endif
