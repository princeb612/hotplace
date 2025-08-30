/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_extension(tls_handshake* handshake, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        // extension
        //  uint16 type
        //  uint16 len
        //  ...
        if (pos + 4 > size) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        {
            auto extension_type = ntoh16(*(uint16*)(stream + pos));
            tls_extension_builder builder;
            auto extension = builder.set(handshake).set(dir).set(extension_type).build();
            if (extension) {
                ret = extension->read(dir, stream, size, pos);
                extension->release();
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
