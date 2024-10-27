/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/auth/bearer_credentials.hpp>

namespace hotplace {
namespace net {

bearer_credentials::bearer_credentials() {}

bearer_credentials& bearer_credentials::add(const std::string& client_id, const std::string& access_token) {
    critical_section_guard guard(_lock);
    _bearer_credential.insert(std::make_pair(access_token, client_id));
    return *this;
}

bool bearer_credentials::verify(http_authentication_provider* provider, const std::string& token) {
    bool ret = false;

    critical_section_guard guard(_lock);

    std::map<std::string, std::string>::iterator iter = _bearer_credential.find(token);
    if (iter != _bearer_credential.end()) {
        ret = true;
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
