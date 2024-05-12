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

#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/auth/oauth2_credentials.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/server/network_session.hpp>

namespace hotplace {
using namespace io;
namespace net {

/**
 * @brief   OAuth2
 * @comments
 *          response_type   grant_type
 *          code            authorization_code  Authorization Code Grant
 *          token           -                   Implicit Grant
 *          -               password            Resource Owner Password Credentials Grant
 *          -               client_credentials  Client Credentials Grant
 */

enum oauth2_grant_t {
    oauth2_authorization_code = (1 << 0),
    oauth2_implicit = (1 << 1),
    oauth2_resource_owner_password = (1 << 2),
    oauth2_client = (1 << 3),

    oauth2_unsupported = (1 << 31),  // reserved
};

class http_router;

class oauth2_grant_provider {
   public:
    oauth2_grant_provider();
    virtual ~oauth2_grant_provider();

    virtual void authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    virtual void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);

    virtual std::string response_type();
    virtual std::string grant_type();
    virtual oauth2_grant_t type() = 0;

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<oauth2_grant_provider> _instance;
};

class oauth2_authorization_code_grant_provider : public oauth2_grant_provider {
   public:
    oauth2_authorization_code_grant_provider();
    virtual ~oauth2_authorization_code_grant_provider();

    virtual void authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    virtual void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);

    virtual std::string response_type();  // code
    virtual std::string grant_type();     // authorization_code
    virtual oauth2_grant_t type();
};

class oauth2_implicit_grant_provider : public oauth2_grant_provider {
   public:
    oauth2_implicit_grant_provider();
    virtual ~oauth2_implicit_grant_provider();

    virtual void authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router);

    virtual std::string response_type();  // token
    virtual oauth2_grant_t type();
};

class oauth2_resource_owner_password_credentials_grant_provider : public oauth2_grant_provider {
   public:
    oauth2_resource_owner_password_credentials_grant_provider();
    virtual ~oauth2_resource_owner_password_credentials_grant_provider();

    virtual void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);

    virtual std::string grant_type();  // password
    virtual oauth2_grant_t type();
};

class oauth2_client_credentials_grant_provider : public oauth2_grant_provider {
   public:
    oauth2_client_credentials_grant_provider();
    virtual ~oauth2_client_credentials_grant_provider();

    virtual void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);

    virtual std::string grant_type();  // client_credentials
    virtual oauth2_grant_t type();
};

class oauth2_unsupported_provider : public oauth2_grant_provider {
   public:
    oauth2_unsupported_provider();
    virtual ~oauth2_unsupported_provider();

    virtual void authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    virtual void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    virtual oauth2_grant_t type();
};

/**
 * @remarks
 *          // sketch
 *          oauth2_provider oauth2;
 *          oauth2.add(new oauth2_authorization_code_grant_provider)
 *                .add(new oauth2_implicit_grant_provider)
 *                .add(new oauth2_resource_owner_password_credentials_grant_provider)
 *                .add(new oauth2_client_credentials_grant_provider)
 *                .add(new oauth2_unsupported_provider)
 *                .set(oauth2_authorization_endpoint, "/auth/authorize")
 *                .set(oauth2_token_endpoint, "/auth/token")
 *                .set(oauth2_signpage, "/auth/sign")
 *                .set(oauth2_signin, "/auth/signin")
 *                .set_token_endpoint_authentication(new basic_authentication_provider("realm"))
 *                .apply(router);
 *
 *          // simply
 *          oauth2.add(new oauth2_authorization_code_grant_provider) // .add if another grant necessary
 *                .set_token_endpoint_authentication(new basic_authentication_provider("realm"))
 *                .apply(router);
 *
 */
enum oauth2_provider_key_t {
    oauth2_authorization_endpoint = 1,
    oauth2_token_endpoint = 2,
    oauth2_signpage = 3,
    oauth2_signin = 4,
};
class oauth2_provider {
   public:
    oauth2_provider();
    virtual ~oauth2_provider();

    oauth2_provider& add(oauth2_grant_provider* provider);
    oauth2_provider& set(oauth2_provider_key_t key, const std::string& value);
    std::string get(oauth2_provider_key_t key);
    oauth2_provider& set_token_endpoint_authentication(http_authenticate_provider* auth);
    oauth2_provider& apply(http_router& router);

   protected:
    typedef std::map<oauth2_grant_t, oauth2_grant_provider*> oauth2_grant_provider_map_t;
    typedef std::pair<oauth2_grant_provider_map_t::iterator, bool> oauth2_grant_provider_map_pib_t;
    typedef std::map<std::string, oauth2_grant_provider*> oauth2_grant_provider_ref_map_t;
    typedef std::pair<oauth2_grant_provider_ref_map_t::iterator, bool> oauth2_grant_provider_ref_map_pib_t;

    void clear();
    return_t choose(oauth2_grant_provider_ref_map_t& object, const std::string& key, oauth2_grant_provider** provider_upref);

    void authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    void signpage_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    void signin_handler(network_session* session, http_request* request, http_response* response, http_router* router);

   private:
    critical_section _lock;

    oauth2_grant_provider_map_t _providers;

    oauth2_grant_provider_ref_map_t _authorization_providers;
    oauth2_grant_provider_ref_map_t _token_providers;

    std::map<oauth2_provider_key_t, std::string> _values;

    http_authenticate_provider* _token_endpoint_authentication;
};

}  // namespace net
}  // namespace hotplace

#endif
