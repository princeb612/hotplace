/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_extension.hpp>

namespace hotplace {
namespace net {

tls_extension_unknown::tls_extension_unknown(uint16 type, tls_session* session) : tls_extension(type, session) {}

return_t tls_extension_unknown::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    ret = tls_extension::read(stream, size, pos);
    if (errorcode_t::success == ret) {
        pos += get_length();
    }
    return ret;
}

return_t tls_extension_unknown::write(binary_t& bin) { return not_supported; }

return_t tls_extension_unknown::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::dump(stream, size, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            //
            // s->printf(" > not supported yet\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
