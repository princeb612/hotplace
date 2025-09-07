/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>

namespace hotplace {
namespace net {

return_t quic_dump_frame(tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        quic_frames frames(session);
        frames.read(dir, stream, size, pos);
    }
    __finally2 {}
    return ret;
}

return_t quic_dump_frame(tls_session* session, const binary_t frame, size_t& pos, tls_direction_t dir) {
    return quic_dump_frame(session, &frame[0], frame.size(), pos);
}

}  // namespace net
}  // namespace hotplace
