/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *  RFC 7617 The 'Basic' HTTP Authentication Scheme
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/auth/basic_authentication_provider.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

basic_authentication_provider::basic_authentication_provider(const std::string& realm) : http_authentication_provider(realm) {}

basic_authentication_provider::~basic_authentication_provider() {}

bool basic_authentication_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response) {
    bool ret_value = false;
    __try2 {
        if (nullptr == resolver || nullptr == session || nullptr == request) {
            __leave2;
        }

        // Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        constexpr char constexpr_authorization[] = "Authorization";
        constexpr char constexpr_basic[] = "Basic";
        std::string token_scheme;
        request->get_http_header().get_token(constexpr_authorization, 0, token_scheme);

        if (0 == strcmp(constexpr_basic, token_scheme.c_str())) {
            ret_value = resolver->basic_authenticate(this, session, request, response);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t basic_authentication_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 2617 2 Basic Authentication Scheme
        response->get_http_header().add("WWW-Authenticate", format("Basic realm=\"%s\"", _realm.c_str()));

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
