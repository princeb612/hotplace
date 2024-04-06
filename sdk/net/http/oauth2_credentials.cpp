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

access_token_t::access_token_t(std::string const& client_id, std::string const& access_token, std::string const& refresh_token, uint16 expire)
    : _client_id(client_id), _access_token(access_token), _refresh_token(refresh_token) {
    _shared.make_share(this);
}

std::string access_token_t::access_token() const { return _access_token; }

std::string access_token_t::refresh_token() const { return _refresh_token; }

std::string access_token_t::client_id() const { return _client_id; }

bool access_token_t::expired() {
    bool ret_value = false;
    timespan_t ts;
    ts.seconds = _expire;
    ret_value = _time.elapsed(ts);
    return ret_value;
}

time_t access_token_t::expire_time() {
    time_t ret_value = 0;
    struct timespec ts;
    _time.gettimespec(&ts);
    ret_value = ts.tv_sec + _expire;
    return ret_value;
}

void access_token_t::addref() { _shared.addref(); }

void access_token_t::release() { _shared.delref(); }

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

return_t oauth2_credentials::grant_code(std::string& code, uint16 expire) {
    return_t ret = errorcode_t::success;

    openssl_prng prng;
    code = prng.rand(16, encoding_t::encoding_base64url);

    _lock.enter();
    time_t t = time(nullptr) + expire;
    _grant_codes.insert(t, code);
    _lock.leave();

    return ret;
}

return_t oauth2_credentials::verify_grant_code(std::string const& code) {
    return_t ret = errorcode_t::success;

    _lock.enter();
    ret = _grant_codes.find(code);
    _lock.leave();

    return ret;
}

return_t oauth2_credentials::expire_grant_codes() {
    return_t ret = errorcode_t::success;
    _lock.enter();
    ret = _grant_codes.expire();
    _lock.leave();
    return ret;
}

return_t oauth2_credentials::clear_grant_codes() {
    return_t ret = errorcode_t::success;
    _lock.enter();
    ret = _grant_codes.clear();
    _lock.leave();
    return ret;
}

return_t oauth2_credentials::grant(std::string& access_token, std::string& refresh_token, std::string const& client_id, uint16 expire) {
    return_t ret = errorcode_t::success;
    access_token_t* token = nullptr;
    __try2 {
        _lock.enter();

        if (client_id.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        webapps_t::iterator iter = _webapps.find(client_id);
        if (_webapps.end() == iter) {
            ret = errorcode_t::invalid_client;
            __leave2;
        }

        std::string atoken, rtoken;
        openssl_prng prng;
        return_t test = errorcode_t::success;
        while (1) {
            atoken = prng.rand(16, encoding_t::encoding_base64url, false);
            test = _access_tokens.find(atoken);
            if (errorcode_t::not_found == test) {
                break;
            }
        }
        while (1) {
            rtoken = prng.rand(16, encoding_t::encoding_base64url, false);
            test = _refresh_tokens.find(rtoken);
            if (errorcode_t::not_found == test) {
                break;
            }
        }

        __try_new_catch(token, new access_token_t(client_id, atoken, rtoken, expire), ret, __leave2);  // refcounter = 1

        _access_tokens.insert(atoken, token, [](access_token_t* object) -> void {});
        _refresh_tokens.insert(atoken, token, [](access_token_t* object) -> void { object->addref(); });
        _expirable.insert(token->expire_time(), token, [](access_token_t* object) -> void { object->addref(); });

        access_token = atoken;
        refresh_token = rtoken;
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::revoke(std::string const& access_token) {
    return_t ret = errorcode_t::success;
    __try2 {
        _lock.enter();

        std::string refresh_token;
        {
            ret = _access_tokens.remove(access_token, [&](access_token_t* object) -> void {
                refresh_token = object->refresh_token();
                object->release();
            });
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        {
            ret = _refresh_tokens.remove(refresh_token, [&](access_token_t* object) -> void { object->release(); });
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::isvalid(std::string const& access_token) {
    return_t ret = errorcode_t::failed;
    __try2 {
        _lock.enter();

        access_token_t* token = nullptr;
        ret = _access_tokens.find(access_token, &token);
        if (errorcode_t::success != ret) {
            __leave2;
        }

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
    __finally2 { _lock.leave(); }
    return ret;
}

return_t oauth2_credentials::refresh(std::string& next_access_token, std::string& next_refresh_token, std::string const& refresh_token, uint16 expire) {
    return_t ret = errorcode_t::success;
    __try2 {
        _lock.enter();

        access_token_t* token = nullptr;
        ret = _refresh_tokens.find(refresh_token, &token);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::string access_token = token->access_token();
        std::string clientid = token->client_id();

        revoke(access_token);
        ret = grant(next_access_token, next_refresh_token, clientid, expire);
    }
    __finally2 { _lock.leave(); }
    return ret;
}

void oauth2_credentials::revoke_if_expired() {
    _lock.enter();
    _expirable.expire([&](access_token_t* object) -> void {
        revoke(object->access_token());
        object->release();
    });
    _lock.leave();
}

void oauth2_credentials::clear() {
    _lock.enter();
    {
        _access_tokens.clear([](access_token_t* object) -> void { object->release(); });
        _refresh_tokens.clear([](access_token_t* object) -> void { object->release(); });
        _expirable.clear([](access_token_t* object) -> void { object->release(); });
    }
    _user_clientid.clear();
    _webapps.clear();
    _lock.leave();
}

}  // namespace net
}  // namespace hotplace
