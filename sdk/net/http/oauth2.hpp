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
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/oauth2_credentials.hpp>
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

class http_router;
class oauth2_provider {
   public:
    oauth2_provider();
    virtual ~oauth2_provider();
};

class oauth2_authorizationcode_provider : public oauth2_provider {
   public:
    oauth2_authorizationcode_provider();
    virtual ~oauth2_authorizationcode_provider();

    void authorization_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    void signin_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    void token_handler(network_session* session, http_request* request, http_response* response, http_router* router);
};

class oauth2_implicit_provider : public oauth2_provider {
   public:
    oauth2_implicit_provider();
    virtual ~oauth2_implicit_provider();
};

class oauth2_resource_owner_password_provider : public oauth2_provider {
   public:
    oauth2_resource_owner_password_provider();
    virtual ~oauth2_resource_owner_password_provider();
};

class oauth2_client_provider : public oauth2_provider {
   public:
    oauth2_client_provider();
    virtual ~oauth2_client_provider();
};

oauth2_provider* build_oauth2_provider(oauth2_grant_t type);

}  // namespace net
}  // namespace hotplace

#endif
