/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/net/http/auth/bearer_authentication_provider.hpp>
#include <sdk/net/http/http_authentication_resolver.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_response.hpp>

namespace hotplace {
namespace net {

bearer_authentication_provider::bearer_authentication_provider(const std::string& realm) : http_authentication_provider(realm) {}

bearer_authentication_provider::~bearer_authentication_provider() {}

bool bearer_authentication_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request,
                                              http_response* response) {
    bool ret_value = false;
    __try2 {
        if (nullptr == resolver || nullptr == session || nullptr == request) {
            __leave2;
        }

        std::string token_scheme;
        request->get_http_header().get_token("Authorization", 0, token_scheme);

        if ("Bearer" != token_scheme) {
            __leave2;
        }

        ret_value = resolver->bearer_authenticate(this, session, request, response);
    }
    __finally2 {}
    return ret_value;
}

return_t bearer_authentication_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        response->get_http_header().add("WWW-Authenticate", format("Bearer realm=\"%s\"", get_realm().c_str()));

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {}
    return ret;
}

std::string bearer_authentication_provider::get_challenge(http_request* request) {
    std::string challenge;

    __try2 { request->get_http_header().get("Authorization", challenge); }
    __finally2 {}

    return challenge;
}

}  // namespace net
}  // namespace hotplace
