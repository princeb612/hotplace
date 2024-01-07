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
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

http_basic_authenticate_provider::http_basic_authenticate_provider(const char* realm) : http_authenticate_provider(realm) {}

http_basic_authenticate_provider::~http_basic_authenticate_provider() {}

bool http_basic_authenticate_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        constexpr char constexpr_authorization[] = "Authorization";
        constexpr char constexpr_basic[] = "Basic";
        std::string token_scheme;
        std::string token_auth;
        request->get_header()->get_token(constexpr_authorization, 0, token_scheme);
        request->get_header()->get(constexpr_authorization, token_auth);

        if (0 == strcmp(constexpr_basic, token_scheme.c_str())) {
            ret_value = resolver->basic_authenticate(this, session, request, token_auth);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t http_basic_authenticate_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        response->get_header()->add("WWW-Authenticate", format("Basic realm=\"%s\"", _realm.c_str()));

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

http_digest_access_authenticate_provider::http_digest_access_authenticate_provider(const char* realm) : http_authenticate_provider(realm) {}

http_digest_access_authenticate_provider::~http_digest_access_authenticate_provider() {}

bool http_digest_access_authenticate_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // Authorization: Digest username="test", realm="Protected", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/login",
        // response="dc17f5db4addad1490b3f565064c3621", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000001, cnonce="3ceef920aacfb49e"
        constexpr char constexpr_authorization[] = "Authorization";
        constexpr char constexpr_digest[] = "Digest";
        std::string token_scheme;
        std::string token_auth;
        request->get_header()->get_token(constexpr_authorization, 0, token_scheme);
        request->get_header()->get(constexpr_authorization, token_auth);

        if (0 == strcmp(constexpr_digest, token_scheme.c_str())) {
            ret_value = resolver->digest_authenticate(this, session, request, token_auth);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_digest_access_authenticate_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_prng prng;
        std::string qop;
        std::string nonce;
        std::string opaque;

        qop = "auth,auth-int";  // quality of protection, "auth" authentication/"auth-int" authentication with integrity protection
        nonce = prng.nonce(16);
        opaque = prng.nonce(16);
        session->get_session_data()->set("nonce", nonce);    // should be uniquely generated each time a 401 response is made
        session->get_session_data()->set("opaque", opaque);  // should be returned by the client unchanged in the Authorization header of subsequent requests

        std::string cred = format("Digest realm=\"%s\", qop=\"%s\", nonce=\"%s\", opaque=\"%s\"", _realm.c_str(), qop.c_str(), nonce.c_str(), opaque.c_str());
        response->get_header()->add("WWW-Authenticate", cred);

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

http_bearer_authenticate_provider::http_bearer_authenticate_provider(const char* realm) : http_authenticate_provider(realm) {}

http_bearer_authenticate_provider::~http_bearer_authenticate_provider() {}

bool http_bearer_authenticate_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char constexpr_authorization[] = "Authorization";
        constexpr char constexpr_bearer[] = "Bearer";
        std::string token_scheme;
        std::string token_auth;
        request->get_header()->get_token(constexpr_authorization, 0, token_scheme);
        request->get_header()->get(constexpr_authorization, token_auth);

        if (0 == strcmp(constexpr_bearer, token_scheme.c_str())) {
            ret_value = true;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_bearer_authenticate_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        response->get_header()->add("WWW-Authenticate", format("Bearer realm=\"%s\"", _realm.c_str()));

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

http_authenticate_resolver::http_authenticate_resolver() : _basic_resolver(nullptr) {}

return_t http_authenticate_resolver::resolve(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;

    bool test = provider->try_auth(this, session, request);
    if (false == test) {
        ret = errorcode_t::mismatch;
    }
    return ret;
}

http_authenticate_resolver& http_authenticate_resolver::basic_resolver(authenticate_handler_t resolver) {
    _basic_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::basic_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                    std::string const& auth) {
    bool ret_value = false;
    size_t pos = 0;
    tokenize(auth, " ", pos);                     // Basic
    std::string cred = tokenize(auth, " ", pos);  // Credentials
    ret_value = _basic_resolver(provider, session, request, cred);
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::digest_resolver(authenticate_handler_t resolver) {
    _digest_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::digest_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     std::string const& auth) {
    bool ret_value = false;
    size_t pos = 0;
    tokenize(auth, " ", pos);             // Digest
    std::string cred = auth.substr(pos);  // Credentials
    ret_value = _digest_resolver(provider, session, request, cred);
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::bearer_resolver(authenticate_handler_t resolver) {
    _bearer_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     std::string const& auth) {
    bool ret_value = false;
    size_t pos = 0;
    tokenize(auth, " ", pos);                     // Bearer
    std::string cred = tokenize(auth, " ", pos);  // Credentials
    ret_value = _bearer_resolver(provider, session, request, cred);
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
