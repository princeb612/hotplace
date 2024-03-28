/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6749 OAuth 2.0
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
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/http_authentication_resolver.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_router.hpp>
#include <sdk/net/http/oauth2.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

oauth2_authorizationcode_provider::oauth2_authorizationcode_provider() : oauth2_provider() {}

oauth2_authorizationcode_provider::~oauth2_authorizationcode_provider() {}

oauth2_implicit_provider::oauth2_implicit_provider() : oauth2_provider() {}

oauth2_implicit_provider::~oauth2_implicit_provider() {}

oauth2_resource_owner_password_provider::oauth2_resource_owner_password_provider() : oauth2_provider() {}

oauth2_resource_owner_password_provider::~oauth2_resource_owner_password_provider() {}

oauth2_client_provider::oauth2_client_provider() : oauth2_provider() {}

oauth2_client_provider::~oauth2_client_provider() {}

oauth2_provider* build_oauth2_provider(oauth2_grant_t type) {
    oauth2_provider* provider = nullptr;
    switch (type) {
        case oauth2_grant_t::oauth2_authorization_code:
            __try_new_catch_only(provider, new oauth2_authorizationcode_provider);
            break;
        case oauth2_grant_t::oauth2_resource_owner_password_credentials:
            __try_new_catch_only(provider, new oauth2_resource_owner_password_provider);
            break;
        case oauth2_grant_t::oauth2_client_credentials:
            __try_new_catch_only(provider, new oauth2_client_provider);
            break;
        default:  // oauth2_grant_t::oauth2_implicit
            __try_new_catch_only(provider, new oauth2_implicit_provider);
            break;
    }
    return provider;
}

}  // namespace net
}  // namespace hotplace
