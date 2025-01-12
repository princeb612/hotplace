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

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   ec_point_formats (0x000b)
 */
class tls_extension_ec_point_formats : public tls_extension {
   public:
    tls_extension_ec_point_formats(tls_session* session);

    tls_extension_ec_point_formats& add_format(uint8 fmt);
    std::list<uint8>& get_formats();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);

   private:
    std::list<uint8> _ec_point_formats;
};

}  // namespace net
}  // namespace hotplace

#endif
