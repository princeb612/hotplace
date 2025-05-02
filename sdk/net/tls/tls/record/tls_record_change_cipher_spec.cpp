/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_record_change_cipher_spec::tls_record_change_cipher_spec(tls_session* session) : tls_record(tls_content_type_change_cipher_spec, session) {}

return_t tls_record_change_cipher_spec::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    if (session) {
        session->get_session_info(dir).begin_protection();
        session->reset_recordno(dir);
#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            std::string dirstr = (from_server == dir) ? "server" : "client";
            dbs.println("> change_cipher_spec %s", dirstr.c_str());
            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif
    }
    return ret;
}

return_t tls_record_change_cipher_spec::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 5246 7.1.  Change Cipher Spec Protocol
        // RFC 4346 7.1. Change Cipher Spec Protocol
        // struct {
        //     enum { change_cipher_spec(1), (255) } type;
        // } ChangeCipherSpec;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record_change_cipher_spec::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    binary_append(bin, uint8(1));
    return ret;
}

}  // namespace net
}  // namespace hotplace
