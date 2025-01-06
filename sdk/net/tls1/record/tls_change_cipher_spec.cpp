/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_record.hpp>

namespace hotplace {
namespace net {

tls_change_cipher_spec::tls_change_cipher_spec(tls_session* session) : tls_record(tls_content_type_change_cipher_spec, session) {}

return_t tls_change_cipher_spec::read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        {
            auto session = get_session();

            // RFC 5246 7.1.  Change Cipher Spec Protocol
            // RFC 4346 7.1. Change Cipher Spec Protocol
            // struct {
            //     enum { change_cipher_spec(1), (255) } type;
            // } ChangeCipherSpec;

            // ret = tls_dump_change_cipher_spec(s, session, stream, size, tpos);
            session->get_session_info(dir).change_cipher_spec();
            session->reset_recordno(dir);
        }

        if (debugstream) {
            //
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_change_cipher_spec::write(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
