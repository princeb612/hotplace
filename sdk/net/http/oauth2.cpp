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
#include <sdk/net/http/http.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/oauth2.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

oauth2_credentials::oauth2_credentials() {}

oauth2_credentials::~oauth2_credentials() {}

return_t oauth2_credentials::register_webapp(std::string& client_id, std::string& client_secret, std::string const& userid, std::string const& appname,
                                             std::string const& redirect_uri, std::list<std::string> scope) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

return_t oauth2_credentials::unregister_webapp(std::string const& client_id) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

return_t oauth2_credentials::grant_access_token(std::string& access_token, std::string& refresh_token, std::string const& client_id, uint16 expire) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

return_t oauth2_credentials::revoke_access_token(std::string const& access_token) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

return_t oauth2_credentials::valid_access_token(std::string const& access_token) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

return_t oauth2_credentials::refresh_token(std::string& next_access_token, std::string& next_refresh_token, std::string const& refresh_token, uint16 expire) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

oauth2_authorizationcode_provider::oauth2_authorizationcode_provider() : http_authenticate_provider("") {}

oauth2_authorizationcode_provider::~oauth2_authorizationcode_provider() {}

bool oauth2_authorizationcode_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request,
                                                 http_response* response) {
    bool ret_value = false;
    return ret_value;
}

return_t oauth2_authorizationcode_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

std::string oauth2_authorizationcode_provider::get_challenge(http_request* request) { return ""; }

oauth2_implicit_provider::oauth2_implicit_provider() : http_authenticate_provider("") {}

oauth2_implicit_provider::~oauth2_implicit_provider() {}

bool oauth2_implicit_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response) {
    bool ret_value = false;
    return ret_value;
}

return_t oauth2_implicit_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

std::string oauth2_implicit_provider::get_challenge(http_request* request) { return ""; }

oauth2_resource_owner_password_provider::oauth2_resource_owner_password_provider() : http_authenticate_provider("") {}

oauth2_resource_owner_password_provider::~oauth2_resource_owner_password_provider() {}

bool oauth2_resource_owner_password_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request,
                                                       http_response* response) {
    bool ret_value = false;
    return ret_value;
}

return_t oauth2_resource_owner_password_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

std::string oauth2_resource_owner_password_provider::get_challenge(http_request* request) { return ""; }

oauth2_client_provider::oauth2_client_provider() : http_authenticate_provider("") {}

oauth2_client_provider::~oauth2_client_provider() {}

bool oauth2_client_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response) {
    bool ret_value = false;
    return ret_value;
}

return_t oauth2_client_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ...
    }
    __finally2 {
        // ...
    }
    return ret;
}

std::string oauth2_client_provider::get_challenge(http_request* request) { return ""; }

http_authenticate_provider* build_oauth2_provider(oauth2_grant_t type) {
    http_authenticate_provider* provider = nullptr;
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
