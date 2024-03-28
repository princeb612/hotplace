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

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

class access_token {
   public:
    access_token(std::string const& client_id, std::string const& accesstoken, std::string const& refreshtoken, uint16 expire);

    std::string atoken() const;
    std::string rtoken() const;
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

    t_shared_reference<access_token> _shared;
};

class oauth2_credentials {
   public:
    oauth2_credentials();
    ~oauth2_credentials();

    /**
     * @brief   register an web application
     * @param   std::string& client_id [out]
     * @param   std::string& client_secret [out]
     * @param   std::string const& userid [in]
     * @param   std::string const& appname [in]
     * @param   std::string const& redirect_uri [in]
     * @param   std::list<std::string> scope [in]
     */
    return_t add(std::string& client_id, std::string& client_secret, std::string const& userid, std::string const& appname, std::string const& redirect_uri,
                 std::list<std::string> scope);
    /**
     * @brief   add (load from db, ...)
     * @param   std::string const& client_id [in]
     * @param   std::string const& client_secret [in]
     * @param   std::string const& userid [in]
     * @param   std::string const& appname [in]
     * @param   std::string const& redirect_uri [in]
     * @param   std::list<std::string> scope [in]
     */
    return_t insert(std::string const& client_id, std::string const& client_secret, std::string const& userid, std::string const& appname,
                    std::string const& redirect_uri, std::list<std::string> scope);
    /**
     * @brief   unregister an web application
     * @param   std::string const& client_id [in]
     */
    return_t remove(std::string const& client_id);
    /**
     * @brief   check
     */
    return_t check(std::string const& client_id, std::string const& redirect_uri);

    /**
     * @brief   list of client_id
     */
    return_t list(std::string const& userid, std::list<std::string>& clientid);

    /**
     * @brief   access_token
     * @param   std::string& access_token [out]
     * @param   std::string& refresh_token [out]
     * @param   std::string const& client_id [in]
     * @param   uint16 expire [inopt]
     */
    return_t grant(std::string& access_token, std::string& refresh_token, std::string const& client_id, uint16 expire = 60 * 60);
    /**
     * @brief   revoke an access_token
     * @param   std::string const& access_token [in]
     */
    return_t revoke(std::string const& access_token);
    /**
     * @brief   validate
     * @param   std::string const& access_token [in]
     */
    return_t isvalid(std::string const& access_token);
    /**
     * @brief   refresh
     * @param   std::string& next_access_token [out]
     * @param   std::string& next_refresh_token [out]
     * @param   std::string const& refresh_token [in]
     * @param   uint16 expire [inopt]
     */
    return_t refresh(std::string& next_access_token, std::string& next_refresh_token, std::string const& refresh_token, uint16 expire = 60 * 60);

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

    typedef std::map<std::string, access_token*> tokens_t;  // map<access_token, class access_token*>
    tokens_t _access_tokens;
    tokens_t _refresh_tokens;

    typedef std::multimap<time_t, access_token*> expire_t;
    expire_t _expires;
};

}  // namespace net
}  // namespace hotplace

#endif
