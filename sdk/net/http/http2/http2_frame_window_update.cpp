/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http2_frame_window_update.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_window_update.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_window_update::http2_frame_window_update() : http2_frame(h2_frame_t::h2_frame_window_update), _increment(0) {}

http2_frame_window_update::http2_frame_window_update(const http2_frame_window_update& other) : http2_frame(other), _increment(other._increment) {}

http2_frame_window_update::~http2_frame_window_update() {}

return_t http2_frame_window_update::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream) && (pos < size); })
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(uint32(0), true, constexpr_frame_window_size_increment);

            auto rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

            _increment = pl.t_value_of<uint32>(constexpr_frame_window_size_increment);

            return success;
        });
    return pipeline.result();
}

return_t http2_frame_window_update::do_write_body(binary_t& body) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(_increment, true, constexpr_frame_window_size_increment);

            auto rc = pl.write(body);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

            return set_payload_size(body.size());
        });
    return pipeline.result();
}

void http2_frame_window_update::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s %u\n", constexpr_frame_window_size_increment, _increment);
    }
}

}  // namespace net
}  // namespace hotplace
