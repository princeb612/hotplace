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
#include <sdk/net/http/http.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

http_authenticate_provider::http_authenticate_provider(std::string const& realm) : _realm(realm) { _shared.make_share(this); }

std::string http_authenticate_provider::get_challenge(http_request* request) {
    std::string token_auth;
    constexpr char constexpr_authorization[] = "Authorization";
    request->get_http_header().get(constexpr_authorization, token_auth);
    return token_auth;
}

int http_authenticate_provider::addref() { return _shared.addref(); }

int http_authenticate_provider::release() { return _shared.delref(); }

std::string http_authenticate_provider::get_realm() { return _realm; }

}  // namespace net
}  // namespace hotplace
