/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http2_frame_rst_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_rst_stream.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_rst_stream::http2_frame_rst_stream() : http2_frame(h2_frame_t::h2_frame_rst_stream), _errorcode(0) {}

http2_frame_rst_stream::http2_frame_rst_stream(const http2_frame_rst_stream& other) : http2_frame(other), _errorcode(other._errorcode) {}

http2_frame_rst_stream::~http2_frame_rst_stream() {}

return_t http2_frame_rst_stream::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;
    payload pl;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() { return (nullptr != stream); })
        .run_trycatch([&]() -> return_t {
            pl << new payload_member((uint32)0, true, constexpr_frame_error_code);
            return pl.read(stream, size, pos);
        })
        .walk([&]() -> void { _errorcode = pl.t_value_of<uint32>(constexpr_frame_error_code); });
    return pipeline.result();
}

return_t http2_frame_rst_stream::do_write_body(binary_t& body) {
    function_pipeline<return_t> pipeline;
    payload pl;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            pl << new payload_member(_errorcode, true, constexpr_frame_error_code);
            return pl.write(body);
        })
        .run([&]() -> return_t { return set_payload_size(body.size()); })
        .walk([&]() -> void {});
    return pipeline.result();
}

void http2_frame_rst_stream::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s %u\n", constexpr_frame_error_code, _errorcode);
    }
}

}  // namespace net
}  // namespace hotplace
