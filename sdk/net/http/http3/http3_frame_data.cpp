/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frame_data.hpp>
#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

http3_frame_data::http3_frame_data() : http3_frame(h3_frame_data) {}

return_t http3_frame_data::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http3_frame_data::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
