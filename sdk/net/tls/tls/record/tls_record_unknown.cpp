/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/tls/record/tls_record_unknown.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_record_unknown::tls_record_unknown(uint8 type, tls_session* session) : tls_record(type, session) {}

tls_record_unknown::~tls_record_unknown() {}

return_t tls_record_unknown::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t tls_record_unknown::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
