/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/quic/quic.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

std::string tls_advisor::quic_param_string(uint64 code) {
    std::string value;
    auto iter = _quic_trans_param_codes.find(code);
    if (_quic_trans_param_codes.end() == iter) {
        value = "undocumented";
    } else {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::quic_frame_type_string(uint64 code) {
    std::string value;
    auto iter = _quic_frame_type_codes.find(code);
    if (_quic_frame_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::quic_error_string(uint64 code) {
    std::string value;
    auto iter = _quic_trans_error_codes.find(code);
    if (_quic_trans_error_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

}  // namespace net
}  // namespace hotplace
