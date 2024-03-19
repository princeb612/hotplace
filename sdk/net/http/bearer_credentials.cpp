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
#include <sdk/net/http/bearer_credentials.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

bearer_credentials::bearer_credentials() {}

bearer_credentials& bearer_credentials::add(std::string const& client_id, std::string const& access_token) {
    critical_section_guard guard(_lock);
    _bearer_credential.insert(std::make_pair(access_token, client_id));
    return *this;
}

bool bearer_credentials::verify(http_authenticate_provider* provider, std::string const& token) {
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
