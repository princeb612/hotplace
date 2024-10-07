/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

// studying

qpack_session::qpack_session() : http_header_compression_session() {}

match_result_t qpack_session::match(const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;
    return state;
}

return_t qpack_session::select(uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::success;
    ret = errorcode_t::reserved;
    return ret;
}

return_t qpack_session::insert(const std::string& name, const std::string& value) {
    return_t ret = errorcode_t::success;
    ret = errorcode_t::reserved;
    return ret;
}

}  // namespace net
}  // namespace hotplace
