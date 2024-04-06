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
#include <sdk/io/basic/json.hpp>
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

oauth2_grant_provider::oauth2_grant_provider() { _instance.make_share(this); }

oauth2_grant_provider::~oauth2_grant_provider() {}

void oauth2_grant_provider::authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router) {}

void oauth2_grant_provider::token_handler(network_session* session, http_request* request, http_response* response, http_router* router) {}

std::string oauth2_grant_provider::response_type() { return ""; }

std::string oauth2_grant_provider::grant_type() { return ""; }

void oauth2_grant_provider::addref() { _instance.addref(); }

void oauth2_grant_provider::release() { _instance.delref(); }

oauth2_authorization_code_grant_provider::oauth2_authorization_code_grant_provider() : oauth2_grant_provider() {}

oauth2_authorization_code_grant_provider::~oauth2_authorization_code_grant_provider() {}

void oauth2_authorization_code_grant_provider::authorization_handler(network_session* session, http_request* request, http_response* response,
                                                                     http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();

    std::string client_id = kv.get("client_id");
    std::string redirect_uri = kv.get("redirect_uri");
    std::string state = kv.get("state");
    basic_stream response_location;

    std::string signpage_uri = router->get_oauth2_provider().get(oauth2_provider_key_t::oauth2_signpage);

    return_t check = router->get_authenticate_resolver().get_oauth2_credentials().check(client_id, redirect_uri);
    if (errorcode_t::success == check) {
        response->get_http_header().add("Location", signpage_uri);
        response->compose(302);

        session->get_session_data()->set("redirect_uri", redirect_uri);
        session->get_session_data()->set("state", state);
    } else {
        // 4.1.2.1.  Error Response
        // HTTP/1.1 302 Found
        // Location: https://client.example.com/cb?error=access_denied&state=xyz
        std::string errorcode;
        error_advisor* advisor = error_advisor::get_instance();
        advisor->error_code(check, errorcode);
        response_location << redirect_uri << "?error=" << errorcode << "&state=" << state;
        response->get_http_header().add("Location", response_location.c_str());
        response->compose(302);
    }
}

void oauth2_authorization_code_grant_provider::token_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    basic_stream body;
    json_t* root = nullptr;
    std::string grant_type = kv.get("grant_type");

    __try2 {
        root = json_object();
        if (nullptr == root) {
            __leave2;
        }

        std::string access_token;
        std::string refresh_token;
        uint16 expire = 60 * 60;

        std::string code = kv.get("code");
        return_t test = router->get_authenticate_resolver().get_oauth2_credentials().verify_grant_code(code);
        if (errorcode_t::success == test) {
            router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, kv.get("client_id"), expire);
            response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");

            json_object_set_new(root, "access_token", json_string(access_token.c_str()));
            json_object_set_new(root, "token_type", json_string("example"));
            json_object_set_new(root, "expire_in", json_integer(expire));
            json_object_set_new(root, "refresh_token", json_string(refresh_token.c_str()));
            json_object_set_new(root, "example_parameter", json_string("example_value"));
        } else {
            json_object_set_new(root, "error", json_string("invalid_request"));
        }
    }
    __finally2 {
        if (root) {
            char* contents = json_dumps(root, JOSE_JSON_FORMAT);
            if (contents) {
                body = contents;
                free(contents);
            }
            json_decref(root);
        } else {
            body << "{\"error\":\"server_error\"}";
        }
    }

    response->compose(200, "application/json", body.c_str());
}

std::string oauth2_authorization_code_grant_provider::response_type() { return "code"; }

std::string oauth2_authorization_code_grant_provider::grant_type() { return "authorization_code"; }

oauth2_grant_t oauth2_authorization_code_grant_provider::type() { return oauth2_grant_t::oauth2_authorization_code; }

oauth2_implicit_grant_provider::oauth2_implicit_grant_provider() : oauth2_grant_provider() {}

oauth2_implicit_grant_provider::~oauth2_implicit_grant_provider() {}

void oauth2_implicit_grant_provider::authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();

    std::string client_id = kv.get("client_id");
    std::string redirect_uri = kv.get("redirect_uri");
    std::string state = kv.get("state");
    basic_stream response_location;

    return_t check = router->get_authenticate_resolver().get_oauth2_credentials().check(client_id, redirect_uri);
    if (errorcode_t::success == check) {
        std::string access_token;
        std::string refresh_token;
        uint16 expire = 60 * 60;

        router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, client_id, expire);

        response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");
        response_location << redirect_uri << "#access_token=" << access_token << "&state=" << state << "&expire_in=" << expire;
        response->get_http_header().add("Location", response_location.c_str());
        response->compose(302);
    } else {
        std::string errorcode;
        error_advisor* advisor = error_advisor::get_instance();
        advisor->error_code(check, errorcode);
        response_location << redirect_uri << "?error=" << errorcode << "&state=" << state;
        response->get_http_header().add("Location", response_location.c_str());
        response->compose(302);
    }
}

std::string oauth2_implicit_grant_provider::response_type() { return "token"; }

oauth2_grant_t oauth2_implicit_grant_provider::type() { return oauth2_grant_t::oauth2_implicit; }

oauth2_resource_owner_password_credentials_grant_provider::oauth2_resource_owner_password_credentials_grant_provider() : oauth2_grant_provider() {}

oauth2_resource_owner_password_credentials_grant_provider::~oauth2_resource_owner_password_credentials_grant_provider() {}

void oauth2_resource_owner_password_credentials_grant_provider::token_handler(network_session* session, http_request* request, http_response* response,
                                                                              http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    basic_stream body;
    json_t* root = nullptr;
    std::string grant_type = kv.get("grant_type");

    __try2 {
        root = json_object();
        if (nullptr == root) {
            __leave2;
        }

        std::string access_token;
        std::string refresh_token;
        uint16 expire = 60 * 60;

        std::string username = kv.get("username");
        std::string password = kv.get("password");

        bool test = router->get_authenticate_resolver().get_custom_credentials().verify(nullptr, username, password);
        if (test) {
            router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, kv.get("client_id"), expire);
            response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");

            json_object_set_new(root, "access_token", json_string(access_token.c_str()));
            json_object_set_new(root, "token_type", json_string("example"));
            json_object_set_new(root, "expire_in", json_integer(expire));
            json_object_set_new(root, "refresh_token", json_string(refresh_token.c_str()));
            json_object_set_new(root, "example_parameter", json_string("example_value"));
        } else {
            json_object_set_new(root, "error", json_string("access_denied"));
        }
    }
    __finally2 {
        if (root) {
            char* contents = json_dumps(root, JOSE_JSON_FORMAT);
            if (contents) {
                body = contents;
                free(contents);
            }
            json_decref(root);
        } else {
            body << "{\"error\":\"server_error\"}";
        }
    }

    response->compose(200, "application/json", body.c_str());
}

std::string oauth2_resource_owner_password_credentials_grant_provider::grant_type() { return "password"; }

oauth2_grant_t oauth2_resource_owner_password_credentials_grant_provider::type() { return oauth2_grant_t::oauth2_resource_owner_password; }

oauth2_client_credentials_grant_provider::oauth2_client_credentials_grant_provider() : oauth2_grant_provider() {}

oauth2_client_credentials_grant_provider::~oauth2_client_credentials_grant_provider() {}

void oauth2_client_credentials_grant_provider::token_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    basic_stream body;
    json_t* root = nullptr;
    std::string grant_type = kv.get("grant_type");

    __try2 {
        root = json_object();
        if (nullptr == root) {
            __leave2;
        }

        std::string access_token;
        std::string refresh_token;
        uint16 expire = 60 * 60;

        router->get_authenticate_resolver().get_oauth2_credentials().grant(access_token, refresh_token, kv.get("client_id"), expire);
        response->get_http_header().clear().add("Cache-Control", "no-store").add("Pragma", "no-cache");

        json_object_set_new(root, "access_token", json_string(access_token.c_str()));
        json_object_set_new(root, "token_type", json_string("example"));
        json_object_set_new(root, "expire_in", json_integer(expire));
        json_object_set_new(root, "refresh_token", json_string(refresh_token.c_str()));
        json_object_set_new(root, "example_parameter", json_string("example_value"));
    }
    __finally2 {
        if (root) {
            char* contents = json_dumps(root, JOSE_JSON_FORMAT);
            if (contents) {
                body = contents;
                free(contents);
            }
            json_decref(root);
        } else {
            body << "{\"error\":\"server_error\"}";
        }
    }

    response->compose(200, "application/json", body.c_str());
}

std::string oauth2_client_credentials_grant_provider::grant_type() { return "client_credentials"; }

oauth2_grant_t oauth2_client_credentials_grant_provider::type() { return oauth2_grant_t::oauth2_client; }

oauth2_unsupported_provider::oauth2_unsupported_provider() : oauth2_grant_provider() {}

oauth2_unsupported_provider::~oauth2_unsupported_provider() {}

oauth2_grant_t oauth2_unsupported_provider::type() { return oauth2_grant_t::oauth2_unsupported; }

void oauth2_unsupported_provider::authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();

    std::string redirect_uri = kv.get("redirect_uri");
    std::string state = kv.get("state");
    basic_stream response_location;
    response_location << redirect_uri << "?error="
                      << "unsupported_response_type"
                      << "&state=" << state;
    response->get_http_header().add("Location", response_location.c_str());
    response->compose(302);
}

void oauth2_unsupported_provider::token_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    basic_stream body;
    json_t* root = nullptr;

    __try2 {
        root = json_object();
        if (nullptr == root) {
            __leave2;
        }

        json_object_set_new(root, "error", json_string("unsupported_grant_type"));
    }
    __finally2 {
        if (root) {
            char* contents = json_dumps(root, JOSE_JSON_FORMAT);
            if (contents) {
                body = contents;
                free(contents);
            }
            json_decref(root);
        } else {
            body << "{\"error\":\"server_error\"}";
        }
    }

    response->compose(200, "application/json", body.c_str());
}

oauth2_provider::oauth2_provider() : _token_endpoint_authentication(nullptr) {
    set(oauth2_provider_key_t::oauth2_authorization_endpoint, "/auth/authorize");
    set(oauth2_provider_key_t::oauth2_token_endpoint, "/auth/token");
    set(oauth2_provider_key_t::oauth2_signpage, "/auth/signpage");
    set(oauth2_provider_key_t::oauth2_signin, "/auth/signin");
}

oauth2_provider::~oauth2_provider() { clear(); }

oauth2_provider& oauth2_provider::add(oauth2_grant_provider* provider) {
    __try2 {
        _lock.enter();

        if (nullptr == provider) {
            __leave2;
        }

        oauth2_grant_provider_map_pib_t pib = _providers.insert(std::make_pair(provider->type(), provider));
        if (pib.second) {
            std::string response_type = provider->response_type();
            if (response_type.size()) {
                _authorization_providers.insert(std::make_pair(response_type, provider));
            }

            std::string grant_type = provider->grant_type();
            if (grant_type.size()) {
                _token_providers.insert(std::make_pair(grant_type, provider));
            }
        }
    }
    __finally2 { _lock.leave(); }
    return *this;
}

oauth2_provider& oauth2_provider::set(oauth2_provider_key_t key, std::string const& value) {
    _values[key] = value;
    return *this;
}

std::string oauth2_provider::get(oauth2_provider_key_t key) {
    std::string ret_value;
    std::map<oauth2_provider_key_t, std::string>::iterator iter = _values.find(key);
    if (_values.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

oauth2_provider& oauth2_provider::set_token_endpoint_authentication(http_authenticate_provider* auth) {
    _token_endpoint_authentication = auth;
    return *this;
}

oauth2_provider& oauth2_provider::apply(http_router& router) {
    router
        .add(get(oauth2_provider_key_t::oauth2_authorization_endpoint),
             [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
                 authorization_handler(session, request, response, router);
             })
        .add(
            get(oauth2_provider_key_t::oauth2_token_endpoint),
            [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
                token_handler(session, request, response, router);
            },
            _token_endpoint_authentication)
        .add(get(oauth2_provider_key_t::oauth2_signpage),
             [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
                 signpage_handler(session, request, response, router);
             })
        .add(get(oauth2_provider_key_t::oauth2_signin),
             [&](network_session* session, http_request* request, http_response* response, http_router* router) -> void {
                 signin_handler(session, request, response, router);
             });
    return *this;
}

void oauth2_provider::clear() {
    critical_section_guard guard(_lock);
    for (auto item : _providers) {
        oauth2_grant_provider* provider = item.second;
        provider->release();
    }
    _providers.clear();
}

return_t oauth2_provider::choose(oauth2_grant_provider_ref_map_t& object, std::string const& key, oauth2_grant_provider** provider_upref) {
    return_t ret = errorcode_t::success;
    oauth2_grant_provider* provider = nullptr;
    __try2 {
        if (nullptr == provider_upref) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);

        oauth2_grant_provider_ref_map_t::iterator iter = object.find(key);
        if (object.end() == iter) {
            oauth2_grant_provider_map_t::iterator piter = _providers.find(oauth2_grant_t::oauth2_unsupported);
            if (_providers.end() == piter) {
                __try_new_catch(provider, new oauth2_unsupported_provider, ret, __leave2);
            } else {
                provider = piter->second;
                provider->addref();
            }
        } else {
            provider = iter->second;
            provider->addref();
        }

        *provider_upref = provider;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void oauth2_provider::authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    return_t ret = errorcode_t::success;
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    std::string response_type = kv.get("response_type");

    oauth2_grant_provider* provider = nullptr;
    __try2 {
        ret = choose(_authorization_providers, response_type, &provider);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        provider->authorization_handler(session, request, response, router);
    }
    __finally2 {
        if (provider) {
            provider->release();
        }
    }
}

void oauth2_provider::token_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    return_t ret = errorcode_t::success;
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    std::string grant_type = kv.get("grant_type");

    oauth2_grant_provider* provider = nullptr;
    __try2 {
        ret = choose(_token_providers, grant_type, &provider);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        provider->token_handler(session, request, response, router);
    }
    __finally2 {
        if (provider) {
            provider->release();
        }
    }
}

void oauth2_provider::signpage_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    constexpr char page[] =
        "<html><head><title>signin</title><meta charset=\"UTF-8\"></head><body><form method=\"post\" action=\"%s\"><table><tr><td "
        "colspan=2>Login</td></tr><tr><td>username</td><td><input type=\"text\" name=\"user\"/></td></tr><tr><td>password</td><td><input type=\"password\" "
        "name=\"pass\"/></td></tr><tr><td/><td><input type=\"submit\"/></td></tr></table></form></body></html>";
    basic_stream bs;
    bs.printf(page, get(oauth2_provider_key_t::oauth2_signin).c_str());
    response->compose(200, "text/html", bs.c_str());
}

void oauth2_provider::signin_handler(network_session* session, http_request* request, http_response* response, http_router* router) {
    basic_stream resp;
    key_value& kv = request->get_http_uri().get_query_keyvalue();
    std::string username = kv.get("user");
    std::string password = kv.get("pass");
    std::string redirect_uri = session->get_session_data()->get("redirect_uri");
    std::string state = session->get_session_data()->get("state");

    bool test = router->get_authenticate_resolver().get_custom_credentials().verify(nullptr, username, password);
    if (test) {
        // RFC 6749 4.1.2.  Authorization Response
        // HTTP/1.1 302 Found
        // Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
        std::string code;
        router->get_authenticate_resolver().get_oauth2_credentials().grant_code(code);
        resp << redirect_uri << "?code=" << code << "&state=" << state;
        response->get_http_header().add("Location", resp.c_str());
        response->compose(302);

        session->get_session_data()->set("code", code);
    } else {
        resp << redirect_uri << "?error=access_denied&state=" << state;
        response->get_http_header().add("Location", resp.c_str());
        response->compose(302);
    }
}

}  // namespace net
}  // namespace hotplace
