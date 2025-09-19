/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_continuation.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_continuation::http2_frame_continuation() : http2_frame(h2_frame_t::h2_frame_continuation) {}

http2_frame_continuation::http2_frame_continuation(const http2_frame_continuation& rhs) : http2_frame(rhs) { _fragment = rhs._fragment; }

http2_frame_continuation::~http2_frame_continuation() {}

return_t http2_frame_continuation::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        payload pl;
        pl << new payload_member(binary_t(), constexpr_frame_fragment);
        pl.read(stream, size, pos);

        pl.get_binary(constexpr_frame_fragment, _fragment);
    }
    __finally2 {}
    return ret;
}

return_t http2_frame_continuation::do_write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_fragment, constexpr_frame_fragment);
    pl.write(body);

    ret = set_payload_size(body.size());

    return ret;
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
