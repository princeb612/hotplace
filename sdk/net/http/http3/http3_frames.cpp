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
#include <sdk/net/http/http3/http3_frame_builder.hpp>
#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>

namespace hotplace {
namespace net {

http3_frames::http3_frames() {}

return_t http3_frames::read(tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (pos < size) {
            uint64 frmtype = 0;
            uint64 frmlen = 0;
            auto tpos = pos;
            ret = quic_read_vle_int(stream, size, tpos, frmtype);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            ret = quic_read_vle_int(stream, size, tpos, frmlen);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (tpos + frmlen > size) {
                ret = errorcode_t::fragmented;
                break;
            }

            h3_frame_t type = (h3_frame_t)frmtype;
            http3_frame_builder builder;
            auto frame = builder.set(type).set(session).build();
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

return_t http3_frames::write(tls_session* session, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto lambda = [&](http3_frame* frame) -> return_t { return frame->write(bin); };
    ret = for_each(lambda);
    return ret;
}

return_t http3_frames::add(http3_frame* frame, bool upref) { return _frames.add(frame, upref); }

http3_frames& http3_frames::operator<<(http3_frame* frame) {
    _frames.add(frame);
    return *this;
}

return_t http3_frames::for_each(std::function<return_t(http3_frame*)> func) { return _frames.for_each(func); }

http3_frame* http3_frames::getat(size_t index, bool upref) { return _frames.getat(index, upref); }

bool http3_frames::empty() { return _frames.empty(); }

size_t http3_frames::size() { return _frames.size(); }

void http3_frames::clear() { _frames.clear(); }

}  // namespace net
}  // namespace hotplace
