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
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/http_authentication_resolver.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/oauth2.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

access_token::access_token(std::string const& client_id, std::string const& accesstoken, std::string const& refreshtoken, uint16 expire)
    : _client_id(client_id), _access_token(accesstoken), _refresh_token(refreshtoken) {
    _shared.make_share(this);
}

std::string access_token::atoken() const { return _access_token; }

std::string access_token::rtoken() const { return _refresh_token; }

std::string access_token::client_id() const { return _client_id; }

bool access_token::expired() {
    bool ret_value = false;
    timespan_t ts;
    ts.seconds = _expire;
    ret_value = _time.elapsed(ts);
    return ret_value;
}

time_t access_token::expire_time() {
    time_t ret_value = 0;
    struct timespec ts;
    _time.gettimespec(&ts);
    ret_value = ts.tv_sec + _expire;
    return ret_value;
}

void access_token::addref() { _shared.addref(); }

void access_token::release() { _shared.delref(); }

oauth2_credentials::oauth2_credentials() {}

oauth2_credentials::~oauth2_credentials() { clear(); }

return_t oauth2_credentials::add(std::string& client_id, std::string& client_secret, std::string const& userid, std::string const& appname,
                                 std::string const& redirect_uri, std::list<std::string> scope) {
    return_t ret = errorcode_t::success;
    __try2 {
        openssl_prng prng;
        do {
            client_id = prng.rand(16, encoding_t::encoding_base64url, false);
            webapps_t::iterator iter = _webapps.find(client_id);
            if (_webapps.end() == iter) {
                break;
            }
        } while (1);

        client_secret = prng.rand(32, encoding_t::encoding_base64url, false);

        ret = insert(client_id, client_secret, userid, appname, redirect_uri, scope);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t oauth2_credentials::insert(std::string const& client_id, std::string const& client_secret, std::string const& userid, std::string const& appname,
                                    std::string const& redirect_uri, std::list<std::string> scope) {
    return_t ret = errorcode_t::success;
    __try2 {
        _lock.enter();

        webapp_t webapp;
        webapp.userid = userid;
        webapp.appname = appname;
        webapp.redirect_uri = redirect_uri;
        webapp.scope = scope;
        webapp.client_id = client_id;
        webapp.client_secret = client_secret;

        _user_clientid.insert(std::make_pair(userid, client_id));
        _webapps.insert(std::make_pair(client_id, webapp));
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::remove(std::string const& client_id) {
    return_t ret = errorcode_t::success;
    __try2 {
        std::string userid;

        _lock.enter();

        {
            webapps_t::iterator iter = _webapps.find(client_id);
            if (_webapps.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            userid = iter->second.userid;
        }

        {
            user_clientid_t::iterator liter = _user_clientid.lower_bound(userid);
            user_clientid_t::iterator uiter = _user_clientid.upper_bound(userid);
            user_clientid_t::iterator iter;
            for (iter = liter; iter != uiter; iter++) {
                if (iter->second == client_id) {
                    _user_clientid.erase(iter);
                    break;
                }
            }
        }
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::check(std::string const& client_id, std::string const& redirect_uri) {
    return_t ret = errorcode_t::success;
    __try2 {
        _lock.enter();

        if (client_id.empty() || redirect_uri.empty()) {
            ret = errorcode_t::invalid_request;
            __leave2;
        }

        webapps_t::iterator iter = _webapps.find(client_id);
        if (_webapps.end() == iter) {
            ret = errorcode_t::unauthorized_client;
            __leave2;
        } else {
            if (redirect_uri != iter->second.redirect_uri) {
                ret = errorcode_t::unauthorized_client;
                __leave2;
            }
        }
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::list(std::string const& userid, std::list<std::string>& clientids) {
    return_t ret = errorcode_t::success;
    __try2 {
        clientids.clear();

        _lock.enter();

        {
            user_clientid_t::iterator liter = _user_clientid.lower_bound(userid);
            user_clientid_t::iterator uiter = _user_clientid.upper_bound(userid);
            user_clientid_t::iterator iter;
            for (iter = liter; iter != uiter; iter++) {
                clientids.push_back(iter->second);
            }
        }
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::grant(std::string& accesstoken, std::string& refreshtoken, std::string const& client_id, uint16 expire) {
    return_t ret = errorcode_t::success;
    access_token* token = nullptr;
    __try2 {
        _lock.enter();

        if (client_id.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string atoken, rtoken;
        openssl_prng prng;
        do {
            atoken = prng.rand(16, encoding_t::encoding_base64url, false);
            tokens_t::iterator iter = _access_tokens.find(atoken);
            if (_access_tokens.end() == iter) {
                break;
            }
        } while (1);
        do {
            rtoken = prng.rand(16, encoding_t::encoding_base64url, false);
            tokens_t::iterator iter = _refresh_tokens.find(atoken);
            if (_refresh_tokens.end() == iter) {
                break;
            }
        } while (1);

        __try_new_catch(token, new access_token(client_id, atoken, rtoken, expire), ret, __leave2);
        _access_tokens.insert(std::make_pair(atoken, token));

        token->addref();
        _refresh_tokens.insert(std::make_pair(rtoken, token));

        token->addref();
        _expires.insert(std::make_pair(token->expire_time(), token));
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::revoke(std::string const& accesstoken) {
    return_t ret = errorcode_t::success;
    __try2 {
        _lock.enter();

        access_token* token = nullptr;
        std::string rtoken;
        {
            tokens_t::iterator iter = _access_tokens.find(accesstoken);
            if (_access_tokens.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            token = iter->second;
            rtoken = token->rtoken();

            token->release();
            _access_tokens.erase(iter);
        }

        {
            tokens_t::iterator iter = _refresh_tokens.find(rtoken);
            if (_refresh_tokens.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            }

            token = iter->second;
            token->release();
            _refresh_tokens.erase(iter);
        }
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::isvalid(std::string const& accesstoken) {
    return_t ret = errorcode_t::failed;
    __try2 {
        _lock.enter();

        access_token* token = nullptr;
        {
            tokens_t::iterator iter = _access_tokens.find(accesstoken);
            if (_access_tokens.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            token = iter->second;

            // client_id validation
            std::string client_id = token->client_id();
            webapps_t::iterator appiter = _webapps.find(client_id);
            if (_webapps.end() == appiter) {
                ret = errorcode_t::expired;
                __leave2;
            }

            // token validation
            bool test = token->expired();
            if (test) {
                ret = errorcode_t::expired;
                __leave2;
            }
            ret = errorcode_t::success;
        }
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::refresh(std::string& next_access_token, std::string& next_refresh_token, std::string const& refreshtoken, uint16 expire) {
    return_t ret = errorcode_t::success;
    __try2 {
        _lock.enter();

        access_token* token = nullptr;
        std::string atoken;
        std::string clientid;
        {
            tokens_t::iterator iter = _refresh_tokens.find(refreshtoken);
            if (_refresh_tokens.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            token = iter->second;
            atoken = token->atoken();
            clientid = token->client_id();
        }

        revoke(atoken);
        ret = grant(next_access_token, next_refresh_token, clientid, expire);
    }
    __finally2 { _lock.leave(); }
    return ret;
}

void oauth2_credentials::revoke_if_expired() {
    datetime dt;
    struct timespec ts;
    dt.gettimespec(&ts);
    time_t now = ts.tv_sec;

    _lock.enter();
    expire_t::iterator iter;
    for (iter = _expires.begin(); iter != _expires.end(); iter++) {
        if (iter->first < now) {
            break;  // future
        } else {
            // past
            access_token* token = iter->second;
            revoke(token->atoken());
            token->release();
            _expires.erase(iter);
        }
    }
    _lock.leave();
}

void oauth2_credentials::clear() {
    _lock.enter();
    {
        tokens_t::iterator iter;
        for (iter = _access_tokens.begin(); iter != _access_tokens.end(); iter++) {
            access_token* token = iter->second;
            token->release();
        }
        _access_tokens.clear();

        for (iter = _refresh_tokens.begin(); iter != _refresh_tokens.end(); iter++) {
            access_token* token = iter->second;
            token->release();
        }
        _refresh_tokens.clear();

        expire_t::iterator exp_iter;
        for (exp_iter = _expires.begin(); exp_iter != _expires.end(); exp_iter++) {
            access_token* token = iter->second;
            token->release();
        }
        _expires.clear();
    }
    _user_clientid.clear();
    _webapps.clear();
    _lock.leave();
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
