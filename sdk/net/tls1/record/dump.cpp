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

#include <sdk/net/tls1/record/tls_record.hpp>
#include <sdk/net/tls1/record/tls_record_builder.hpp>
#include <sdk/net/tls1/tls.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_record(tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            uint8 content_type = stream[pos];
            tls_record_builder builder;
            auto record = builder.set(session).set(content_type).build();
            if (record) {
                ret = record->read(dir, stream, size, pos);
                record->release();
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
