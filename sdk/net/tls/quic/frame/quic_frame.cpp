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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame::quic_frame(quic_frame_t type, tls_session* session) : _type(type), _session(session) {
    if (session) {
        session->addref();
    }
    _shared.make_share(this);
}

quic_frame::~quic_frame() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t quic_frame::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        size_t begin = pos;

        // RFC 9001 19.  Frame Types and Formats
        uint64 type = 0;
        ret = quic_read_vle_int(stream, size, pos, type);
        if (errorcode_t::success != ret) {
            __leave2;
        }

#if defined DEBUG
        if (istraceable(category_net)) {
            basic_stream dbs;
            dbs.println("  > frame %s @%zi", tlsadvisor->quic_frame_type_string(type).c_str(), begin);
            trace_debug_event(category_net, net_event_quic_dump, &dbs);
        }
#endif

        ret = do_read_header(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_read_body(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_postprocess(dir);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_frame::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t body;
        ret = do_write_body(dir, body);

        ret = do_write_header(dir, bin, body);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_postprocess(dir);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_frame::do_preprocess(tls_direction_t dir) { return errorcode_t::success; }

return_t quic_frame::do_postprocess(tls_direction_t dir) { return errorcode_t::success; }

return_t quic_frame::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return errorcode_t::success; }

return_t quic_frame::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return errorcode_t::success; }

return_t quic_frame::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) { return errorcode_t::success; }

return_t quic_frame::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

quic_frame_t quic_frame::get_type() { return _type; }

void quic_frame::set_type(uint64 type) { _type = (quic_frame_t)type; }

tls_session* quic_frame::get_session() { return _session; }

void quic_frame::addref() { _shared.addref(); }

void quic_frame::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
