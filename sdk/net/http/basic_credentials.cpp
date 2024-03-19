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
#include <sdk/net/http/basic_credentials.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

basic_credentials::basic_credentials() {}

basic_credentials& basic_credentials::add(std::string const& username, std::string const& password) {
    basic_stream bs;
    bs << username << ":" << password;

    std::string challenge = base64_encode(bs.data(), bs.size());
    return add(challenge);
}

basic_credentials& basic_credentials::add(std::string const& challenge) {
    critical_section_guard guard(_lock);
    _basic_credential.insert(challenge);
    return *this;
}

bool basic_credentials::verify(http_authenticate_provider* provider, std::string const& credential) {
    bool ret = false;

    critical_section_guard guard(_lock);
    std::set<std::string>::iterator iter = _basic_credential.find(credential);
    ret = (_basic_credential.end() != iter);

    return ret;
}

}  // namespace net
}  // namespace hotplace
