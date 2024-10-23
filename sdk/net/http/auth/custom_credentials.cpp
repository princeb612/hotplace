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
#include <sdk/net/http/auth/custom_credentials.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

custom_credentials::custom_credentials() {}

custom_credentials& custom_credentials::add(const std::string& username, const std::string& password) {
    critical_section_guard guard(_lock);
    openssl_digest dgst;
    std::string password_hash;
    dgst.digest("sha512", password, password_hash, encoding_t::encoding_base64url);
    _custom_credential.insert(std::make_pair(username, password_hash));
    return *this;
}

bool custom_credentials::verify(http_authentication_provider* provider, const std::string& username, const std::string& password) {
    bool ret = false;
    critical_section_guard guard(_lock);
    openssl_digest dgst;
    std::string password_hash;
    dgst.digest("sha512", password, password_hash, encoding_t::encoding_base64url);
    std::map<std::string, std::string>::iterator iter = _custom_credential.find(username);
    if (_custom_credential.end() != iter) {
        if (password_hash == iter->second) {
            ret = true;
        }
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
