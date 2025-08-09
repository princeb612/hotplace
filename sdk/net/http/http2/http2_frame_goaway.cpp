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
#include <sdk/net/http/http2/http2_frame_goaway.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_goaway::http2_frame_goaway() : http2_frame(h2_frame_t::h2_frame_goaway), _last_id(0), _errorcode(0) {}

http2_frame_goaway::http2_frame_goaway(const http2_frame_goaway& rhs) : http2_frame(rhs), _last_id(rhs._last_id), _errorcode(rhs._errorcode) {
    _debug = rhs._debug;
}

http2_frame_goaway::~http2_frame_goaway() {}

return_t http2_frame_goaway::read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_last_stream_id)  //
           << new payload_member((uint32)0, true, constexpr_frame_error_code)      //
           << new payload_member(binary_t(), constexpr_frame_debug_data);

        pl.read(stream, size, pos);

        _last_id = pl.t_value_of<uint32>(constexpr_frame_last_stream_id);
        _errorcode = pl.t_value_of<uint32>(constexpr_frame_error_code);
        pl.get_binary(constexpr_frame_debug_data, _debug);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_goaway::write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_last_id, true, constexpr_frame_last_stream_id)  //
       << new payload_member(_errorcode, true, constexpr_frame_error_code)    //
       << new payload_member(_debug, constexpr_frame_debug_data);
    pl.write(body);

    ret = set_payload_size(body.size());

    return ret;
}

void http2_frame_goaway::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s %u\n", constexpr_frame_last_stream_id, _last_id);
        s->printf(" > %s %u\n", constexpr_frame_error_code, _errorcode);
        s->printf(" > %s\n", constexpr_frame_debug_data);
        dump_memory(_debug, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
    }
}

http2_frame_goaway& http2_frame_goaway::set_errorcode(uint32 errorcode) {
    _errorcode = errorcode;
    return *this;
}

void http2_frame_goaway::set_debug(const binary_t& debug) { _debug = debug; }

const binary_t& http2_frame_goaway::get_debug() { return _debug; }

}  // namespace net
}  // namespace hotplace
