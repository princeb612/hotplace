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
#include <sdk/net/http/http_authenticate.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

oauth2_provider::oauth2_provider(const char* realm) : http_authenticate_provider(realm) {}

oauth2_provider::~oauth2_provider() {}

bool oauth2_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response) {
    bool ret_value = false;
    __try2 {
        if (nullptr == session || nullptr == request) {
            __leave2;
        }

        constexpr char constexpr_authorization[] = "Authorization";
        constexpr char constexpr_bearer[] = "Bearer";
        std::string token_scheme;
        request->get_http_header().get_token(constexpr_authorization, 0, token_scheme);

        if (constexpr_bearer == token_scheme) {
            //
        } else if (request->get_http_header().contains("Content-Type", "application/x-www-form-urlencoded")) {
            //
        } else {
            __leave2;
        }

        ret_value = resolver->oauth2_authenticate(this, session, request, response);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t oauth2_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string session_bearer = session->get_session_data()->get("bearer");
        if ("access_token" == session_bearer) {
            session->get_session_data()->remove("bearer");

            openssl_prng prng;
            std::string access_token = prng.token(16);
            std::string refresh_token = prng.token(16);
            session->get_session_data()->set("access_token", access_token);
            session->get_session_data()->set("refresh_token", refresh_token);

            response->compose(200, "application/json", "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"refresh_token\":\"%s\"}", access_token.c_str(),
                              refresh_token.c_str());
        } else {
            response->get_http_header().add("WWW-Authenticate", format("Bearer realm=\"%s\"", _realm.c_str()));

            int status_code = 401;
            std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
            response->compose(status_code, "text/html", body.c_str());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

std::string oauth2_provider::get_challenge(http_request* request) {
    std::string challenge;

    __try2 {
        constexpr char constexpr_authorization[] = "Authorization";
        request->get_http_header().get(constexpr_authorization, challenge);
        if (false == challenge.empty()) {
            __leave2;
        }

        if (request->get_http_header().contains("Content-Type", "application/x-www-form-urlencoded")) {
            challenge = request->get_content();
        }
    }
    __finally2 {
        // do nothing
    }

    return challenge;
}

}  // namespace net
}  // namespace hotplace
