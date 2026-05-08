/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   dump.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_extension(tls_handshake* handshake, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_parameter([&]() { return (nullptr != handshake) && (nullptr != stream); })
        .run([&]() -> return_t {
            // extension
            //  uint16 type
            //  uint16 len
            //  ...
            return (pos + 4 > size) ? no_more : success;
        })
        .run([&]() ->return_t {
            return_t ret = success;
            auto extension_type = ntoh16(*(uint16*)(stream + pos));
            tls_extension_builder builder;
            auto extension = builder.set(handshake).set(dir).set(extension_type).build();
            if (extension) {
                ret = extension->read(dir, stream, size, pos);
                extension->release();
            }
            return ret;
        });
    return pipeline.result();
}

}  // namespace net
}  // namespace hotplace
