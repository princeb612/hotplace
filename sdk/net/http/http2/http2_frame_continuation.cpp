/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http2_frame_continuation.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_continuation.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_continuation::http2_frame_continuation() : http2_frame(h2_frame_t::h2_frame_continuation) {}

http2_frame_continuation::http2_frame_continuation(const http2_frame_continuation& other) : http2_frame(other) { _fragment = other._fragment; }

http2_frame_continuation::~http2_frame_continuation() {}

return_t http2_frame_continuation::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .goahead_if_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream); })
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_frame_fragment);

            auto rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                __trace_return(rc);
            }

            pl.get_binary(constexpr_frame_fragment, _fragment);

            return success;
        });
    return pipeline.result();
}

return_t http2_frame_continuation::do_write_body(binary_t& body) {
    function_pipeline<return_t> pipeline;

    pipeline
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(_fragment, constexpr_frame_fragment);
            return pl.write(body);
        })
        .run([&]() -> return_t { return set_payload_size(body.size()); });
    return pipeline.result();
}

void http2_frame_continuation::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);

        auto lambda = [&](const std::string& name, const std::string& value) -> void { s->printf(" > %s: %s\n", name.c_str(), value.c_str()); };
        http2_frame::read_compressed_header(_fragment, lambda);
    }
}

void http2_frame_continuation::set_fragment(const binary_t& fragment) { _fragment = fragment; }

const binary_t& http2_frame_continuation::get_fragment() { return _fragment; }

}  // namespace net
}  // namespace hotplace
