/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/basic_authentication_provider.hpp>
#include <sdk/net/http/custom_credentials.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

custom_credentials::custom_credentials() {}

custom_credentials& custom_credentials::add(std::string const& username, std::string const& password) {
    critical_section_guard guard(_lock);
    openssl_digest dgst;
    std::string password_hash;
    dgst.digest("sha512", password, password_hash, encoding_t::encoding_base64url);
    _custom_credential.insert(std::make_pair(username, password_hash));
    return *this;
}

bool custom_credentials::verify(http_authenticate_provider* provider, std::string const& username, std::string const& password) {
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
