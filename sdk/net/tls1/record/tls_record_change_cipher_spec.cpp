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
#include <sdk/net/tls1/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_record_change_cipher_spec::tls_record_change_cipher_spec(tls_session* session) : tls_record(tls_content_type_change_cipher_spec, session) {}

return_t tls_record_change_cipher_spec::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    if (session) {
        session->get_session_info(dir).change_cipher_spec();
        session->reset_recordno(dir);
    }
    return ret;
}

return_t tls_record_change_cipher_spec::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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

return_t tls_record_change_cipher_spec::do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    binary_append(bin, uint8(1));
    return ret;
}

}  // namespace net
}  // namespace hotplace
