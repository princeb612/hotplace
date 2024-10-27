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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
namespace net {

http2_frame_continuation::http2_frame_continuation() : http2_frame(h2_frame_t::h2_frame_continuation) {}

http2_frame_continuation::http2_frame_continuation(const http2_frame_continuation& rhs) : http2_frame(rhs) { _fragment = rhs._fragment; }

return_t http2_frame_continuation::read(http2_frame_header_t const* header, size_t size) {
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
        pl << new payload_member(binary_t(), constexpr_frame_fragment);

        pl.read(ptr_payload, get_payload_size());

        pl.select(constexpr_frame_fragment)->get_variant().to_binary(_fragment);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_continuation::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_fragment, constexpr_frame_fragment);

    binary_t bin_payload;
    pl.write(bin_payload);

    set_payload_size(bin_payload.size());

    http2_frame::write(frame);
    frame << bin_payload;

    return ret;
}

void http2_frame_continuation::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");

        auto lambda = [&](const std::string& name, const std::string& value) -> void { s->printf(" > %s: %s\n", name.c_str(), value.c_str()); };
        http2_frame::read_compressed_header(_fragment, lambda);
    }
}

binary_t& http2_frame_continuation::get_fragment() { return _fragment; }

}  // namespace net
}  // namespace hotplace
