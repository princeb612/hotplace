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
#include <sdk/net/http/http_authenticate.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

http_authenticate_resolver::http_authenticate_resolver() : _basic_resolver(nullptr) {}

bool http_authenticate_resolver::resolve(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) {
    return provider->try_auth(this, session, request, response);
}

http_authenticate_resolver& http_authenticate_resolver::basic_resolver(authenticate_handler_t resolver) {
    _basic_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::basic_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                    http_response* response) {
    bool ret_value = false;
    if (_basic_resolver) {
        ret_value = _basic_resolver(provider, session, request, response);
    }
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::digest_resolver(authenticate_handler_t resolver) {
    _digest_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::digest_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     http_response* response) {
    bool ret_value = false;
    if (_digest_resolver) {
        ret_value = _digest_resolver(provider, session, request, response);
    }
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::bearer_resolver(authenticate_handler_t resolver) {
    _bearer_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     http_response* response) {
    bool ret_value = false;
    if (_bearer_resolver) {
        ret_value = _bearer_resolver(provider, session, request, response);
    }
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::oauth2_resolver(authenticate_handler_t resolver) {
    _oauth2_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::oauth2_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     http_response* response) {
    bool ret_value = false;
    if (_bearer_resolver) {
        ret_value = _oauth2_resolver(provider, session, request, response);
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
