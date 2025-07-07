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
#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>

namespace hotplace {
namespace net {

http3_frames::http3_frames() {}

return_t http3_frames::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        while (pos < size) {
            uint64 value = 0;
            auto tpos = pos;
            ret = quic_read_vle_int(stream, size, tpos, value);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            h3_frame_t type = (h3_frame_t)value;
            http3_frame_builder builder;
            auto frame = builder.set(type).build();
            if (frame) {
                ret = frame->read(stream, size, pos);
                frame->release();

                if (errorcode_t::success != ret) {
                    break;
                }
            } else {
                break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t http3_frames::write(const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;

    return ret;
}

}  // namespace net
}  // namespace hotplace
