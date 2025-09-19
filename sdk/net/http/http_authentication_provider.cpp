/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/http/http_authentication_provider.hpp>
#include <hotplace/sdk/net/http/http_request.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
// #include <hotplace/sdk/net/http/http_response.hpp>
#include <hotplace/sdk/net/server/network_session.hpp>

namespace hotplace {
namespace net {

http_authentication_provider::http_authentication_provider(const std::string& realm) : _realm(realm) { _shared.make_share(this); }

std::string http_authentication_provider::get_challenge(http_request* request) {
    std::string token_auth;
    request->get_http_header().get("Authorization", token_auth);
    return token_auth;
}

int http_authentication_provider::addref() { return _shared.addref(); }

int http_authentication_provider::release() { return _shared.delref(); }

const std::string& http_authentication_provider::get_realm() const { return _realm; }

}  // namespace net
}  // namespace hotplace
