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
    __try2 {
        if (_basic_resolver) {
            ret_value = _basic_resolver(provider, session, request, response);
        } else {
            std::string challenge = provider->get_challenge(request);

            size_t pos = 0;
            tokenize(challenge, " ", pos);                           // Basic
            std::string credential = tokenize(challenge, " ", pos);  // base64(user:password)

            critical_section_guard guard(_lock);
            std::set<std::string>::iterator iter = _basic_credential.find(credential);
            ret_value = (_basic_credential.end() != iter);

            if (ret_value) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
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
    __try2 {
        if (_digest_resolver) {
            ret_value = _digest_resolver(provider, session, request, response);
        } else {
            return_t ret = errorcode_t::success;
            http_digest_access_authenticate_provider* digest_provider = (http_digest_access_authenticate_provider*)provider;
            key_value kv;

            ret = digest_provider->prepare_digest_access(session, request, response, kv);
            if (errorcode_t::success == ret) {
                // get username from kv.get("username"), and then read password (cache, in-memory db)
                // and then call provider->auth_digest_access

                critical_section_guard guard(_lock);

                std::string username = kv.get("username");
                std::string password;
                if (digest_provider->get_userhash()) {
                    std::map<std::string, std::string>::iterator iter_userhash = _digest_access_userhash.find(username);
                    if (_digest_access_userhash.end() != iter_userhash) {
                        kv.set("username", iter_userhash->second);
                        password = _digest_access_credential[iter_userhash->second];
                    }
                } else {
                    std::map<std::string, std::string>::iterator iter = _digest_access_credential.find(username);
                    if (_digest_access_credential.end() != iter) {
                        password = iter->second;
                    }
                }
                if (password.size()) {
                    kv.set("password", password);
                    ret = digest_provider->auth_digest_access(session, request, response, kv);
                    if (errorcode_t::success == ret) {
                        ret_value = true;
                    }
                }
            }
        }
    }
    __finally2 {
        // do nothing
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
    } else {
        std::string challenge = provider->get_challenge(request);
        std::string token;

        if (0 == strncmp("Bearer", challenge.c_str(), 6)) {
            size_t pos = 6;
            token = tokenize(challenge, " ", pos);
            if (token == session->get_session_data()->get("access_token")) {
                ret_value = true;
            }
        } else {
            key_value kv;
            http_uri::to_keyvalue(challenge, kv);
            token = kv.get("access_token");
            std::string client_id = kv.get("client_id");
            std::string client_secret = kv.get("client_secret");

            critical_section_guard guard(_lock);

            std::map<std::string, std::string>::iterator iter = _bearer_credential.find(client_id);
            if (iter != _bearer_credential.end()) {
                session->get_session_data()->set("bearer", "access_token");  // hmm... I need something grace
            }
        }
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
    } else {
        std::string challenge = provider->get_challenge(request);
        std::string token;

        if (0 == strncmp("Bearer", challenge.c_str(), 6)) {
            size_t pos = 6;
            token = tokenize(challenge, " ", pos);
            if (token == session->get_session_data()->get("access_token")) {
                ret_value = true;
            }
        } else {
            key_value kv;
            http_uri::to_keyvalue(challenge, kv);
            token = kv.get("access_token");
            std::string client_id = kv.get("client_id");
            std::string client_secret = kv.get("client_secret");

            critical_section_guard guard(_lock);

            std::map<std::string, std::string>::iterator iter = _bearer_credential.find(client_id);
            if (iter != _bearer_credential.end()) {
                session->get_session_data()->set("bearer", "access_token");  // hmm... I need something grace
            }
        }
    }
    return ret_value;
}

http_authenticate_resolver& http_authenticate_resolver::basic_credential(std::string const& username, std::string const& password) {
    basic_stream bs;
    bs << username << ":" << password;

    critical_section_guard guard(_lock);
    _basic_credential.insert(base64_encode(bs.data(), bs.size()));
    return *this;
}

http_authenticate_resolver& http_authenticate_resolver::basic_credential(std::string const& challenge) {
    critical_section_guard guard(_lock);
    _basic_credential.insert(challenge);
    return *this;
}

http_authenticate_resolver& http_authenticate_resolver::digest_access_credential(std::string const& username, std::string const& password) {
    critical_section_guard guard(_lock);
    _digest_access_credential.insert(std::make_pair(username, password));
    return *this;
}

http_authenticate_resolver& http_authenticate_resolver::digest_access_credential(std::string const& realm, std::string const& algorithm,
                                                                                 std::string const& username, std::string const& password) {
    rfc2617_digest dgst;
    dgst.add(username).add(":").add(realm).digest(algorithm);

    critical_section_guard guard(_lock);
    _digest_access_credential.insert(std::make_pair(username, password));
    _digest_access_userhash.insert(std::make_pair(dgst.get(), username));
    return *this;
}

http_authenticate_resolver& http_authenticate_resolver::bearer_credential(std::string const& client_id, std::string const& client_secret) {
    critical_section_guard guard(_lock);
    _bearer_credential.insert(std::make_pair(client_id, client_secret));
    return *this;
}

http_authenticate_resolver& http_authenticate_resolver::add_auth(std::string const& client_id, std::string const& client_secret,
                                                                 std::string const& redirect_uri) {
    critical_section_guard guard(_lock);
    _oauth2_credential.insert(std::make_pair(client_id, client_secret));
    _redirect_uri.insert(std::make_pair(client_id, redirect_uri));
    return *this;
}

/*
bool http_authenticate_resolver::login(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response) {
    bool ret_value = false;
        return_t ret = errorcode_t::success;
        std::string error;
        __try2 {
            key_value kv;

            if (request->get_http_header().contains("Content-Type", "application/x-www-form-urlencoded")) {
                http_header::to_keyvalue(request->get_content(), kv);
            } else {
                http_header::to_keyvalue(request->get_uri(), kv);
            }

            if (kv.empty()) {
                ret = errorcode_t::invalid_request;
                __leave2;
            }

            std::string response_type = kv.get("response_type");
            std::string client_id = kv.get("client_id");
            std::string redirect_uri = kv.get("redirect_uri");

            if ("code" != response_type) {
                ret = errorcode_t::unsupported_response_type;
                __leave2;
            }

            {
                critical_section_guard guard(_lock);

                std::map<std::string, std::string>::iterator iter_redirect = _redirect_uri.find(client_id);
                if (_redirect_uri.end() == iter_redirect) {
                    ret = errorcode_t::unauthorized_client;
                    __leave2;
                }
                std::map<std::string, std::string>::iterator iter_cred = _oauth2_credential.find(client_id);
                if (_oauth2_credential.end() == iter_cred) {
                    ret = errorcode_t::unauthorized_client;
                    __leave2;
                }
            }

            constexpr char constexpr_authorization[] = "Authorization";
            constexpr char constexpr_basic[] = "Basic";
            constexpr char constexpr_digest[] = "Digest";
            std::string token_scheme;
            request->get_http_header().get_token(constexpr_authorization, 0, token_scheme);

            if (0 == strcmp(constexpr_basic, token_scheme.c_str())) {
                ret_value = basic_authenticate(provider, session, request, response);
            } else if (0 == strcmp(constexpr_digest, token_scheme.c_str())) {
                ret_value = digest_authenticate(provider, session, request, response);
            }
            if (false == ret_value) {
                ret = errorcode_t::access_denied;
                __leave2;
            }
        }
        __finally2 {
            // do nothing
        }
    return ret_value;
}
*/

}  // namespace net
}  // namespace hotplace
