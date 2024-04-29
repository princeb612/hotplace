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
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

constexpr char constexpr_frame_length[] = "length";
constexpr char constexpr_frame_type[] = "type";
constexpr char constexpr_frame_flags[] = "flags";
constexpr char constexpr_frame_stream_identifier[] = "stream identifier";
constexpr char constexpr_frame_pad_length[] = "pad length";
constexpr char constexpr_frame_data[] = "data";
constexpr char constexpr_frame_padding[] = "padding";
constexpr char constexpr_frame_stream_dependency[] = "stream dependency";
constexpr char constexpr_frame_weight[] = "weight";
constexpr char constexpr_frame_fragment[] = "fragment";
constexpr char constexpr_frame_priority[] = "priority";
constexpr char constexpr_frame_error_code[] = "error code";
constexpr char constexpr_frame_promised_stream_id[] = "promised stream id";
constexpr char constexpr_frame_opaque[] = "opaque";
constexpr char constexpr_frame_last_stream_id[] = "last stream id";
constexpr char constexpr_frame_debug_data[] = "debug data";
constexpr char constexpr_frame_window_size_increment[] = "window size increment";

constexpr char constexpr_frame_exclusive[] = "exclusive";
constexpr char constexpr_frame_identifier[] = "identifier";
constexpr char constexpr_frame_value[] = "value";

http2_frame_goaway::http2_frame_goaway() : http2_frame_header(h2_frame_t::h2_frame_goaway), _last_id(0), _errorcode(0) {}

return_t http2_frame_goaway::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_last_stream_id) << new payload_member((uint32)0, true, constexpr_frame_error_code)
           << new payload_member(binary_t(), constexpr_frame_debug_data);

        pl.read(ptr_payload, get_payload_size());

        _last_id = t_variant_to_int<uint32>(pl.select(constexpr_frame_last_stream_id)->get_variant().content());
        _errorcode = t_variant_to_int<uint32>(pl.select(constexpr_frame_error_code)->get_variant().content());
        pl.select(constexpr_frame_fragment)->get_variant().dump(_debug, true);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_goaway::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_last_id, true, constexpr_frame_last_stream_id) << new payload_member(_errorcode, true, constexpr_frame_error_code)
       << new payload_member(_debug, constexpr_frame_debug_data);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_frame_goaway::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s %u\n", constexpr_frame_last_stream_id, _last_id);
        s->printf("> %s %u\n", constexpr_frame_error_code, _errorcode);
        s->printf("> %s\n", constexpr_frame_debug_data);
        dump_memory(_debug, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
    }
}

}  // namespace net
}  // namespace hotplace
