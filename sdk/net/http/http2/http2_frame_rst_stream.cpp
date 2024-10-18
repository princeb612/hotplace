/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/io/system/types.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

http2_frame_rst_stream::http2_frame_rst_stream() : http2_frame(h2_frame_t::h2_frame_rst_stream), _errorcode(0) {}

http2_frame_rst_stream::http2_frame_rst_stream(const http2_frame_rst_stream& rhs) : http2_frame(rhs), _errorcode(rhs._errorcode) {}

return_t http2_frame_rst_stream::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_error_code);

        pl.read(ptr_payload, get_payload_size());

        _errorcode = t_to_int<uint32>(pl.select(constexpr_frame_error_code));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_rst_stream::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_errorcode, true, constexpr_frame_error_code);

    binary_t bin_payload;
    pl.write(bin_payload);

    set_payload_size(bin_payload.size());

    http2_frame::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_frame_rst_stream::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s %u\n", constexpr_frame_error_code, _errorcode);
    }
}

}  // namespace net
}  // namespace hotplace
