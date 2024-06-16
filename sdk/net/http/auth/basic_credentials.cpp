/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/auth/basic_authentication_provider.hpp>
#include <sdk/net/http/auth/basic_credentials.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

basic_credentials::basic_credentials() {}

basic_credentials& basic_credentials::add(const std::string& username, const std::string& password) {
    basic_stream bs;
    bs << username << ":" << password;

    std::string challenge = base64_encode(bs.data(), bs.size());
    return add(challenge);
}

basic_credentials& basic_credentials::add(const std::string& challenge) {
    critical_section_guard guard(_lock);
    _basic_credential.insert(challenge);
    return *this;
}

bool basic_credentials::verify(http_authenticate_provider* provider, const std::string& credential) {
    bool ret = false;

    critical_section_guard guard(_lock);
    std::set<std::string>::iterator iter = _basic_credential.find(credential);
    ret = (_basic_credential.end() != iter);

    return ret;
}

}  // namespace net
}  // namespace hotplace
