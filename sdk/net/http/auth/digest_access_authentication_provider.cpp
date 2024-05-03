/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/auth/digest_access_authentication_provider.hpp>
#include <sdk/net/http/auth/rfc2617_digest.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

digest_access_authentication_provider::digest_access_authentication_provider(const std::string& realm)
    : http_authenticate_provider(realm), _qop("auth, auth-int"), _userhash(false) {}

digest_access_authentication_provider::digest_access_authentication_provider(const std::string& realm, const char* algorithm, const char* qop, bool userhash)
    : http_authenticate_provider(realm) {
    set_algorithm(algorithm);
    set_qop(qop);
    set_userhash(userhash);
}

digest_access_authentication_provider::digest_access_authentication_provider(const std::string& realm, const std::string& algorithm, const std::string& qop,
                                                                             bool userhash)
    : http_authenticate_provider(realm), _algorithm(algorithm), _qop(qop), _userhash(userhash) {}

digest_access_authentication_provider::~digest_access_authentication_provider() {}

bool digest_access_authentication_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request,
                                                     http_response* response) {
    bool ret_value = false;
    __try2 {
        if (nullptr == resolver || nullptr == session || nullptr == request) {
            __leave2;
        }

        // Authorization: Digest username="test", realm="Protected", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/login",
        // response="dc17f5db4addad1490b3f565064c3621", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000001, cnonce="3ceef920aacfb49e"
        constexpr char constexpr_authorization[] = "Authorization";
        constexpr char constexpr_digest[] = "Digest";
        std::string token_scheme;
        request->get_http_header().get_token(constexpr_authorization, 0, token_scheme);

        if (0 == strcmp(constexpr_digest, token_scheme.c_str())) {
            ret_value = resolver->digest_authenticate(this, session, request, response);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t digest_access_authentication_provider::request_auth(network_session* session, http_request* request, http_response* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        response->close();
        response->get_http_header().clear();

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
        if (get_userhash()) {
            cred << ", userhash=true";
        }
        response->get_http_header().add("WWW-Authenticate", cred.c_str());

        int status_code = 401;
        std::string body = format("<html><body>%i %s</body></html>", status_code, http_resource::get_instance()->load(status_code).c_str());
        response->compose(status_code, "text/html", body.c_str());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t digest_access_authentication_provider::prepare_digest_access(network_session* session, http_request* request, http_response* response, key_value& kv) {
    return_t ret = errorcode_t::mismatch;
    __try2 {
        if (nullptr == session || nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string opaque_session;
        session->get_session_data()->query("opaque", opaque_session);

        if (false == opaque_session.empty()) {
            std::string challenge = get_challenge(request);
            http_header::to_keyvalue(challenge, kv);

            if (kv.get("nonce") != session->get_session_data()->get("nonce")) {
                __leave2;
            }
            if (kv.get("opaque") != opaque_session) {
                __leave2;
            }
            if (kv.get("realm") != get_realm()) {
                __leave2;
            }
            if (get_userhash() && ("true" != kv.get("userhash"))) {
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

return_t digest_access_authentication_provider::auth_digest_access(network_session* session, http_request* request, http_response* response, key_value& kv) {
    return_t ret = errorcode_t::mismatch;
    __try2 {
        if (nullptr == session || nullptr == request || nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string alg;
        std::string hashalg = get_algorithm();
        std::string qop;

        alg = kv.get("algorithm");
        qop = kv.get("qop");

        rfc2617_digest dgst_a1;
        rfc2617_digest dgst_a2;
        rfc2617_digest dgst_sequence;
        std::string digest_ha1;
        std::string digest_ha2;

        // RFC 2617 3.2.2.2 A1
        dgst_a1.clear().add(kv.get("username")).add(":").add(get_realm()).add(":").add(kv.get("password")).digest(hashalg);
        if (ends_with(alg, "-sess")) {
            digest_ha1 = dgst_a1.add(":").add(kv.get("nonce")).add(":").add(kv.get("cnonce")).digest(hashalg).get();
        } else {
            digest_ha1 = dgst_a1.get();
        }

        // RFC 2617 3.2.2.3 A2
        // If the qop parameter's value is "auth" or is unspecified
        //      A2       = Method ":" digest-uri-value
        // If the qop value is "auth-int"
        //      A2       = Method ":" digest-uri-value ":" H(entity-body)
        dgst_a2.clear().add(request->get_method()).add(":").add(kv.get("uri"));
        if ("auth-int" == qop) {
            // RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
            // 7.2 Entity Body
            basic_stream entity_body(request->get_content().c_str());
            rfc2617_digest entity_dgst;
            entity_dgst.add(entity_body).digest(hashalg);
            dgst_a2.add(":").add(entity_dgst.get());
        }
        digest_ha2 = dgst_a2.digest(hashalg).get();

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
        dgst_sequence.clear().add(digest_ha1).add(":").add(kv.get("nonce"));
        if (("auth" == qop) || ("auth-int" == qop)) {
            dgst_sequence.add(":").add(kv.get("nc")).add(":").add(kv.get("cnonce")).add(":").add(kv.get("qop"));
        }
        dgst_sequence.add(":").add(digest_ha2);
        digest_response = dgst_sequence.digest(hashalg).get();

        // if (1) {
        //     printf("* a1 %s -> %s\n", dgst_a1.get_sequence().c_str(), digest_ha1.c_str());
        //     printf("* a2 %s -> %s\n", dgst_a2.get_sequence().c_str(), digest_ha2.c_str());
        //     printf("* resp %s -> %s\n", dgst_sequence.get_sequence().c_str(), digest_response.c_str());
        // }

        if (digest_response == kv.get("response")) {
            ret = errorcode_t::success;

            // RFC2617 3.2.3 The Authentication-Info Header
            // If the nextnonce field is present the client SHOULD use it when constructing the Authorization header for its next request.
            // but ... chrome, edge don't use nextnonce
#if 0
            std::string nextnonce;
            basic_stream auth_info;
            openssl_prng prng;
            nextnonce = prng.nonce(16);
            auth_info << "nextnonce=\"" << nextnonce << "\"";
            if(qop.size()) {
                auth_info << ", qop=" << qop;
            }
            response->get_http_header().add("Authentication-Info", auth_info.c_str());
            // session->get_session_data()->set("nonce", nextnonce);
#endif
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

digest_access_authentication_provider& digest_access_authentication_provider::set_algorithm(const char* algorithm) {
    if (algorithm) {
        _algorithm = algorithm;
    }
    return *this;
}

digest_access_authentication_provider& digest_access_authentication_provider::set_qop(const char* qop) {
    if (qop) {
        _qop = qop;
    }
    return *this;
}

digest_access_authentication_provider& digest_access_authentication_provider::set_userhash(bool enable) {
    _userhash = enable;
    return *this;
}

std::string digest_access_authentication_provider::get_algorithm() { return _algorithm; }

std::string digest_access_authentication_provider::get_qop() { return _qop; }

bool digest_access_authentication_provider::get_userhash() { return _userhash; }

}  // namespace net
}  // namespace hotplace
