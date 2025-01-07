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

return_t tls_extension_unknown::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    if (debugstream) {
        //
        // s->printf(" > not supported yet\n");
    }
    return ret;
}

return_t tls_extension_unknown::write(binary_t& bin, stream_t* debugstream) { return not_supported; }

}  // namespace net
}  // namespace hotplace
