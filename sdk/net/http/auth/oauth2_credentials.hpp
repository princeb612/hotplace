/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_OAUTH2_CREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_OAUTH2_CREDENTIALS__

#include <functional>
#include <map>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/types.hpp>
#include <set>

namespace hotplace {
namespace net {

/**
 * @brief   tokens (lock required)
 */
template <typename TYPE_T, typename OBJECT_T>
class t_tokens {
   public:
    typedef typename std::map<TYPE_T, OBJECT_T> tokens_map_t;
    typedef typename std::function<void(OBJECT_T)> token_handler_t;

    t_tokens() {}

    return_t insert(TYPE_T key, OBJECT_T object, token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        if (handler) {
            handler(object);
        }
        _tokens.insert(std::make_pair(key, object));
        return ret;
    }

    return_t find(TYPE_T key, OBJECT_T* object = nullptr, token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        __try2 {
            typename tokens_map_t::iterator iter = _tokens.find(key);
            if (_tokens.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                OBJECT_T item = iter->second;
                if (handler) {
                    handler(item);
                }
                if (object) {
                    *object = item;
                }
            }
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }

    return_t remove(TYPE_T key, token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        __try2 {
            typename tokens_map_t::iterator iter = _tokens.find(key);
            if (_tokens.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                OBJECT_T item = iter->second;
                if (handler) {
                    handler(item);
                }
                _tokens.erase(iter);
            }
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }

    return_t clear(token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        if (handler) {
            for (auto item : _tokens) {
                handler(item.second);
            }
        }
        _tokens.clear();
        return ret;
    }

   private:
    tokens_map_t _tokens;
};

/**
 * @brief   expirable (lock required)
 */
template <typename OBJECT_T>
class t_expirable {
   public:
    typedef typename std::multimap<time_t, OBJECT_T> expires_t;
    typedef typename std::function<void(OBJECT_T)> token_handler_t;

    t_expirable() {}
    virtual ~t_expirable() { clear(); }

    virtual return_t insert(time_t time, OBJECT_T object, token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        if (handler) {
            handler(object);
        }
        _expires.insert(std::make_pair(time, object));
        return ret;
    }

    virtual return_t expire(token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        datetime dt;
        struct timespec ts;
        dt.gettimespec(&ts);
        time_t now = ts.tv_sec;

        for (typename expires_t::iterator iter = _expires.begin(); iter != _expires.end();) {
            if (now > iter->first) {
                // past
                if (handler) {
                    handler(iter->second);
                }
                _expires.erase(iter++);
            } else {
                // future
                break;
            }
        }
        return ret;
    }

    virtual return_t clear(token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        if (handler) {
            for (auto item : _expires) {
                handler(item.second);
            }
        }
        _expires.clear();
        return ret;
    }

   protected:
    expires_t _expires;
};

/**
 * @brief   expirable tokens (lock required)
 */
template <typename OBJECT_T>
class t_expirable_tokens : t_expirable<OBJECT_T> {
   public:
    typedef typename std::set<OBJECT_T> tokens_set_t;
    typedef typename std::pair<typename tokens_set_t::iterator, bool> tokens_set_pib_t;
    typedef typename std::function<void(OBJECT_T)> token_handler_t;

    t_expirable_tokens() : t_expirable<OBJECT_T>() {}

    virtual return_t insert(time_t time, OBJECT_T object, token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        tokens_set_pib_t pib = _tokens.insert(object);
        if (pib.second) {
            t_expirable<OBJECT_T>::insert(time, object, handler);
        } else {
            ret = errorcode_t::already_exist;
        }
        return ret;
    }

    virtual return_t find(OBJECT_T object) {
        return_t ret = errorcode_t::success;
        expire();
        typename tokens_set_t::iterator iter = _tokens.find(object);
        if (_tokens.end() == iter) {
            ret = errorcode_t::not_found;
        }
        return ret;
    }

    virtual return_t expire(token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        t_expirable<OBJECT_T>::expire([&](OBJECT_T object) -> void {
            typename tokens_set_t::iterator iter = _tokens.find(object);
            if (_tokens.end() != iter) {
                if (handler) {
                    handler(*iter);
                }
                _tokens.erase(iter);
            }
        });
        return ret;
    }

    virtual return_t clear(token_handler_t handler = nullptr) {
        return_t ret = errorcode_t::success;
        t_expirable<OBJECT_T>::clear(handler);
        _tokens.clear();
        return ret;
    }

   private:
    tokens_set_t _tokens;
};

/**
 * @brief   access token
 */
class access_token_t {
   public:
    access_token_t(const std::string& client_id, const std::string& accesstoken, const std::string& refreshtoken, uint16 expire);

    std::string access_token() const;
    std::string refresh_token() const;
    std::string client_id() const;
    bool expired();
    time_t expire_time();

    void addref();
    void release();

   private:
    std::string _client_id;
    std::string _access_token;
    std::string _refresh_token;
    datetime _time;
    uint16 _expire;

    t_shared_reference<access_token_t> _shared;
};

/**
 * @brief   credentials
 */
class oauth2_credentials {
   public:
    oauth2_credentials();
    ~oauth2_credentials();

    /**
     * @brief   register an web application
     * @param   std::string& client_id [out]
     * @param   std::string& client_secret [out]
     * @param   const std::string& userid [in]
     * @param   const std::string& appname [in]
     * @param   const std::string& redirect_uri [in]
     * @param   std::list<std::string> scope [in]
     */
    return_t add(std::string& client_id, std::string& client_secret, const std::string& userid, const std::string& appname, const std::string& redirect_uri,
                 std::list<std::string> scope);
    /**
     * @brief   add (load from db, ...)
     * @param   const std::string& client_id [in]
     * @param   const std::string& client_secret [in]
     * @param   const std::string& userid [in]
     * @param   const std::string& appname [in]
     * @param   const std::string& redirect_uri [in]
     * @param   std::list<std::string> scope [in]
     */
    return_t insert(const std::string& client_id, const std::string& client_secret, const std::string& userid, const std::string& appname,
                    const std::string& redirect_uri, std::list<std::string> scope);
    /**
     * @brief   unregister an web application
     * @param   const std::string& client_id [in]
     */
    return_t remove(const std::string& client_id);
    /**
     * @brief   check
     */
    return_t check(const std::string& client_id, const std::string& redirect_uri);

    /**
     * @brief   list of client_id
     */
    return_t list(const std::string& userid, std::list<std::string>& clientid);

    return_t grant_code(std::string& code, uint16 expire = 10 * 60);
    return_t verify_grant_code(const std::string& code);
    return_t expire_grant_codes();
    return_t clear_grant_codes();

    /**
     * @brief   access_token
     * @param   std::string& access_token [out]
     * @param   std::string& refresh_token [out]
     * @param   const std::string& client_id [in]
     * @param   uint16 expire [inopt]
     */
    return_t grant(std::string& access_token, std::string& refresh_token, const std::string& client_id, uint16 expire = 60 * 60);
    /**
     * @brief   revoke an access_token
     * @param   const std::string& access_token [in]
     */
    return_t revoke(const std::string& access_token);
    /**
     * @brief   validate
     * @param   const std::string& access_token [in]
     */
    return_t isvalid(const std::string& access_token);
    /**
     * @brief   refresh
     * @param   std::string& next_access_token [out]
     * @param   std::string& next_refresh_token [out]
     * @param   const std::string& refresh_token [in]
     * @param   uint16 expire [inopt]
     */
    return_t refresh(std::string& next_access_token, std::string& next_refresh_token, const std::string& refresh_token, uint16 expire = 60 * 60);

    void revoke_if_expired();

   protected:
    void clear();

   private:
    critical_section _lock;

    /**
     *  web application > client id
     *  login: userid
     *
     *  + add app
     *  = list app
     *    [1] app1 - delete
     *    [2] app2 - delete
     */

    typedef struct _webapp_t {
        std::string userid;

        std::string appname;
        std::string redirect_uri;
        std::list<std::string> scope;

        std::string client_id;
        std::string client_secret;

        std::string email;
        std::string email_developer;

        _webapp_t() {}
        _webapp_t& clear() {
            userid.clear();
            appname.clear();
            redirect_uri.clear();
            scope.clear();
            client_id.clear();
            client_secret.clear();
            email.clear();
            email_developer.clear();
            return *this;
        }
    } webapp_t;

    typedef std::multimap<std::string, std::string> user_clientid_t;  // multimap<userid, client_id>
    typedef std::map<std::string, webapp_t> webapps_t;                // map<client_id, webapp_t>
    typedef std::pair<webapps_t::iterator, bool> webapps_pib_t;
    user_clientid_t _user_clientid;
    webapps_t _webapps;

    t_expirable_tokens<std::string> _grant_codes;

    t_tokens<std::string, access_token_t*> _access_tokens;
    t_tokens<std::string, access_token_t*> _refresh_tokens;
    t_expirable<access_token_t*> _expirable;
};

}  // namespace net
}  // namespace hotplace

#endif
