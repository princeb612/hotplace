/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_OAUTH2__
#define __HOTPLACE_SDK_NET_HTTP_OAUTH2__

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

/**
 *  grant_type
 *          authorization_code  Authorization Code Grant
 *          -                   Implicit Grant
 *          password            Resource Owner Password Credentials Grant
 *          client_credentials  Client Credentials Grant
 */

enum oauth2_grant_t {
    oauth2_authorization_code = 1,
    oauth2_implicit,
    oauth2_resource_owner_password_credentials,
    oauth2_client_credentials,
};

class access_token {
   public:
    access_token() { _shared.make_share(this); }

   private:
    std::string client_id;
    std::string refresh_token;
    uint16 expire;

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
    return_t register_webapp(std::string& client_id, std::string& client_secret, std::string const& userid, std::string const& appname,
                             std::string const& redirect_uri, std::list<std::string> scope);
    /**
     * @brief   unregister an web application
     * @param   std::string const& client_id [in]
     */
    return_t unregister_webapp(std::string const& client_id);

    /**
     * @brief   access_token
     * @param   std::string& access_token [out]
     * @param   std::string& refresh_token [out]
     * @param   std::string const& client_id [in]
     * @param   uint16 expire [inopt]
     */
    return_t grant_access_token(std::string& access_token, std::string& refresh_token, std::string const& client_id, uint16 expire = 60 * 60);
    /**
     * @brief   revoke an access_token
     * @param   std::string const& access_token [in]
     */
    return_t revoke_access_token(std::string const& access_token);
    /**
     * @brief   validate
     * @param   std::string const& access_token [in]
     */
    return_t valid_access_token(std::string const& access_token);
    /**
     * @brief   refresh
     * @param   std::string& next_access_token [out]
     * @param   std::string& next_refresh_token [out]
     * @param   std::string const& refresh_token [in]
     * @param   uint16 expire [inopt]
     */
    return_t refresh_token(std::string& next_access_token, std::string& next_refresh_token, std::string const& refresh_token, uint16 expire = 60 * 60);

   private:
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
        std::string appname;
        std::list<std::string> scope;
        std::string redirect_uri;

        std::string client_id;
        std::string client_secret;

        std::string userid;
        std::string email;
        std::string email_developer;
    } webapp_t;

    typedef std::multimap<std::string, std::string> user_clientid_t;  // multimap<userid, client_id>
    typedef std::map<std::string, webapp_t> webapps_t;                // map<client_id, webapp_t>
    typedef std::pair<webapps_t::iterator, bool> webapps_pib_t;
    user_clientid_t _user_clientid;
    webapps_t _webapps;

    // client_id - (access_token, refresh_token) (1..*)

    // typedef std::map<std::string, access_token_t> access_tokens_t;  // map<access_token, access_token_t>
};

class oauth2_authorizationcode_provider : public http_authenticate_provider {
   public:
    oauth2_authorizationcode_provider();
    virtual ~oauth2_authorizationcode_provider();

    /**
     * @brief   try
     * @param   http_authentication_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   200 OK / 401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);

    virtual std::string get_challenge(http_request* request);
};

class oauth2_implicit_provider : public http_authenticate_provider {
   public:
    oauth2_implicit_provider();
    virtual ~oauth2_implicit_provider();

    /**
     * @brief   try
     * @param   http_authentication_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   200 OK / 401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);

    virtual std::string get_challenge(http_request* request);
};

class oauth2_resource_owner_password_provider : public http_authenticate_provider {
   public:
    oauth2_resource_owner_password_provider();
    virtual ~oauth2_resource_owner_password_provider();

    /**
     * @brief   try
     * @param   http_authentication_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   200 OK / 401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);

    virtual std::string get_challenge(http_request* request);
};

class oauth2_client_provider : public http_authenticate_provider {
   public:
    oauth2_client_provider();
    virtual ~oauth2_client_provider();

    /**
     * @brief   try
     * @param   http_authentication_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   200 OK / 401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);

    virtual std::string get_challenge(http_request* request);
};

http_authenticate_provider* build_oauth2_provider(oauth2_grant_t type);

}  // namespace net
}  // namespace hotplace

#endif
