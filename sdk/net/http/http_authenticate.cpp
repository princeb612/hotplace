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
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

http_basic_authenticate_provider::http_basic_authenticate_provider(const char* realm) : http_authenticate_provider(realm) {}

http_basic_authenticate_provider::~http_basic_authenticate_provider() {}

bool http_basic_authenticate_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request,
                                                http_response* response) {
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
        request->get_header().get_token(constexpr_authorization, 0, token_scheme);

        if (0 == strcmp(constexpr_basic, token_scheme.c_str())) {
            ret_value = resolver->basic_authenticate(this, session, request, response);
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

        response->get_header().add("WWW-Authenticate", format("Basic realm=\"%s\"", _realm.c_str()));

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

rfc2617_digest::rfc2617_digest() {}

rfc2617_digest& rfc2617_digest::add(const char* data) {
    _stream << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::add(std::string const& data) {
    _stream << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::add(basic_stream const& data) {
    _stream << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::operator<<(const char* data) {
    _stream << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::operator<<(std::string const& data) {
    _stream << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::operator<<(basic_stream const& data) {
    _stream << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::digest(std::string const& algorithm) {
    openssl_digest dgst;
    std::string digest_value;
    dgst.digest(algorithm.c_str(), _stream, digest_value);
    _stream = digest_value;
    return *this;
}

std::string rfc2617_digest::get() {
    std::string ret_value;
    ret_value = _stream.c_str();
    return ret_value;
}

rfc2617_digest& rfc2617_digest::clear() {
    _stream.clear();
    return *this;
}

http_digest_access_authenticate_provider::http_digest_access_authenticate_provider(const char* realm)
    : http_authenticate_provider(realm), _qop("auth, auth-int") {}

http_digest_access_authenticate_provider::http_digest_access_authenticate_provider(const char* realm, const char* algorithm, const char* qop)
    : http_authenticate_provider(realm) {
    set_algorithm(algorithm);
    set_qop(qop);
}

http_digest_access_authenticate_provider::~http_digest_access_authenticate_provider() {}

bool http_digest_access_authenticate_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request,
                                                        http_response* response) {
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
        request->get_header().get_token(constexpr_authorization, 0, token_scheme);

        if (0 == strcmp(constexpr_digest, token_scheme.c_str())) {
            ret_value = resolver->digest_authenticate(this, session, request, response);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t http_digest_access_authenticate_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_prng prng;
        std::string nonce;
        std::string opaque;

        nonce = prng.nonce(16);
        opaque = prng.nonce(16);
        session->get_session_data()->set("nonce", nonce);    // should be uniquely generated each time a 401 response is made
        session->get_session_data()->set("opaque", opaque);  // should be returned by the client unchanged in the Authorization header of subsequent requests

        basic_stream cred;
        cred << "Digest realm=\"" << get_realm() << "\"";
        if (false == get_algorithm().empty()) {
            cred << ", algorithm=" << get_algorithm();
        }
        cred << ", qop=\"" << get_qop() << "\", nonce=\"" << nonce << "\", opaque=\"" << opaque << "\"";
        response->get_header().add("WWW-Authenticate", cred.c_str());

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_digest_access_authenticate_provider::prepare_digest_access(network_session* session, http_request* request, http_response* response,
                                                                         key_value& kv) {
    return_t ret = errorcode_t::mismatch;
    __try2 {
        if (nullptr == session || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        std::string opaque_session;
        session->get_session_data()->query("opaque", opaque_session);

        if (false == opaque_session.empty()) {
            std::string challenge = get_challenge(request);
            http_header::to_keyvalue(challenge, kv);

            if (kv.get("realm") != get_realm()) {
                __leave2;
            }
            if (kv.get("nonce") != session->get_session_data()->get("nonce")) {
                __leave2;
            }
            if (kv.get("opaque") != opaque_session) {
                __leave2;
            }
            ret = errorcode_t::success;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_digest_access_authenticate_provider::digest_digest_access(network_session* session, http_request* request, http_response* response,
                                                                        key_value& kv) {
    return_t ret = errorcode_t::mismatch;
    __try2 {
        if (nullptr == session || nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string alg;
        std::string hashalg = "md5";  // default
        std::string qop;

        alg = kv.get("algorithm");
        qop = kv.get("qop");

        // RFC 7616
        //      MD5, SHA-512-256, SHA-256
        //      MD5-sess, SHA-512-256-sess, SHA-256-sess
        std::map<std::string, std::string> algmap;
        algmap.insert(std::make_pair("MD5", "md5"));
        algmap.insert(std::make_pair("MD5-sess", "md5"));
        algmap.insert(std::make_pair("SHA-512-256", "sha2-512/256"));
        algmap.insert(std::make_pair("SHA-512-256-sess", "sha2-512/256"));
        algmap.insert(std::make_pair("SHA-256", "sha256"));
        algmap.insert(std::make_pair("SHA-256-sess", "sha256"));

        if (alg.size()) {
            std::map<std::string, std::string>::iterator alg_iter = algmap.find(alg);
            if (algmap.end() != alg_iter) {
                hashalg = alg_iter->second;
            }
        }

        rfc2617_digest dgst;
        std::string digest_ha1;
        std::string digest_ha2;

        // RFC 2617 3.2.2.2 A1
        dgst.clear().add(kv.get("username")).add(":").add(get_realm()).add(":").add(kv.get("password")).digest(hashalg);
        if (ends_with(alg, "-sess")) {
            digest_ha1 = dgst.add(":").add(kv.get("nonce")).add(":").add(kv.get("cnonce")).digest(hashalg).get();
        } else {
            digest_ha1 = dgst.get();
        }

        // RFC 2617 3.2.2.3 A2
        // If the qop parameter's value is "auth" or is unspecified
        //      A2       = Method ":" digest-uri-value
        // If the qop value is "auth-int"
        //      A2       = Method ":" digest-uri-value ":" H(entity-body)
        dgst.clear().add(request->get_method()).add(":").add(kv.get("uri"));
        if ("auth-int" == qop) {
            // RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
            // 7.2 Entity Body
            basic_stream entity_body(request->get_content().c_str());
            rfc2617_digest entity_dgst;
            entity_dgst.add(entity_body).digest(hashalg);
            dgst.add(":").add(entity_dgst.get());
        }
        digest_ha2 = dgst.digest(hashalg).get();

        // RFC 2617 3.2.2.1 Request-Digest
        // RFC 7616 3.4.1.  Response
        //      If the qop value is "auth" or "auth-int":
        //          request-digest  = <"> < KD ( H(A1),     unq(nonce-value)
        //                                              ":" nc-value
        //                                              ":" unq(cnonce-value)
        //                                              ":" unq(qop-value)
        //                                              ":" H(A2)
        //                                      ) <">
        //
        //      If the "qop" directive is not present
        //          request-digest  =
        //             <"> < KD ( H(A1), unq(nonce-value) ":" H(A2) ) >
        //             <">

        std::string digest_response;
        dgst.clear().add(digest_ha1).add(":").add(kv.get("nonce"));
        if (("auth" == qop) || ("auth-int" == qop)) {
            dgst.add(":").add(kv.get("nc")).add(":").add(kv.get("cnonce")).add(":").add(kv.get("qop"));
        }
        dgst.add(":").add(digest_ha2);
        digest_response = dgst.digest(hashalg).get();

        if (digest_response == kv.get("response")) {
            ret = errorcode_t::success;

#if 0
            // chrome, edge dont response w/ nextnonce
            std::string nextnonce;
            basic_stream auth_info;
            openssl_prng prng;
            nextnonce = prng.nonce(16);
            auth_info << "nextnonce=\"" << nextnonce << "\"";
            if(qop.size()) {
                auth_info << ", qop=" << qop;
            }
            response->get_header().add("Authentication-Info", auth_info.c_str());
            session->get_session_data()->set("nonce", nextnonce);
#endif
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

http_digest_access_authenticate_provider& http_digest_access_authenticate_provider::set_algorithm(const char* algorithm) {
    if (algorithm) {
        _algorithm = algorithm;
    }
    return *this;
}

http_digest_access_authenticate_provider& http_digest_access_authenticate_provider::set_qop(const char* qop) {
    if (qop) {
        _qop = qop;
    }
    return *this;
}

std::string http_digest_access_authenticate_provider::get_algorithm() { return _algorithm; }

std::string http_digest_access_authenticate_provider::get_qop() { return _qop; }

http_bearer_authenticate_provider::http_bearer_authenticate_provider(const char* realm) : http_authenticate_provider(realm) {}

http_bearer_authenticate_provider::~http_bearer_authenticate_provider() {}

bool http_bearer_authenticate_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request,
                                                 http_response* response) {
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
        request->get_header().get_token(constexpr_authorization, 0, token_scheme);
        request->get_header().get(constexpr_authorization, token_auth);

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

        response->get_header().add("WWW-Authenticate", format("Bearer realm=\"%s\"", _realm.c_str()));

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

    bool test = provider->try_auth(this, session, request, response);
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
                                                    http_response* response) {
    bool ret_value = false;
    ret_value = _basic_resolver(provider, session, request, response);
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::digest_resolver(authenticate_handler_t resolver) {
    _digest_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::digest_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     http_response* response) {
    bool ret_value = false;
    ret_value = _digest_resolver(provider, session, request, response);
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::bearer_resolver(authenticate_handler_t resolver) {
    _bearer_resolver = resolver;
    return *this;
}

bool http_authenticate_resolver::bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request,
                                                     http_response* response) {
    bool ret_value = false;
    ret_value = _bearer_resolver(provider, session, request, response);
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
