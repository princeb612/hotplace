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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONECPOINTFORMATS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONECPOINTFORMATS__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   ec_point_formats (0x000b)
 */
class tls_extension_ec_point_formats : public tls_extension {
   public:
    tls_extension_ec_point_formats(tls_handshake* handshake);

    /**
     *  add("x25519") or add(0x001d)
     */
    tls_extension_ec_point_formats& add(uint8 code);
    tls_extension_ec_point_formats& add(const std::string& name);

    void clear();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    std::list<uint8> _ec_point_formats;
};

}  // namespace net
}  // namespace hotplace

#endif
