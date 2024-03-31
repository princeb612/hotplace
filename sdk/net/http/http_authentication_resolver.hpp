/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * spec list
 *      qop=auth
 *      algorithm=MD5|MD5-sess|SHA-256|SHA-256-sess
 *      userhash
 * todo list
 *      qop=auth-int
 *      nextnonce
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_AUTHENTICATION_RESOLVER__
#define __HOTPLACE_SDK_NET_HTTP_AUTHENTICATION_RESOLVER__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/net/http/basic_authentication_provider.hpp>
#include <sdk/net/http/basic_credentials.hpp>
#include <sdk/net/http/bearer_authentication_provider.hpp>
#include <sdk/net/http/bearer_credentials.hpp>
#include <sdk/net/http/custom_credentials.hpp>
#include <sdk/net/http/digest_access_authentication_provider.hpp>
#include <sdk/net/http/digest_credentials.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/oauth2.hpp>

namespace hotplace {
using namespace io;
namespace net {

typedef std::function<bool(http_authenticate_provider*, network_session*, http_request* request, http_response* response)> authenticate_handler_t;

class http_authentication_resolver {
   public:
    http_authentication_resolver();

    /**
     * @brief   resolve
     * @param   http_authenticate_provider* provider [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  result
     */
    bool resolve(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

    /**
     * @brief   register handler
     * @param   authenticate_handler_t resolver [in]
     */
    http_authentication_resolver& basic_resolver(authenticate_handler_t resolver);
    /*
     * @brief   authenticate
     * @param   http_authenticate_provider* provider [in]
     * @param   http_response* response [in]
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool basic_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   register handler
     * @param   authenticate_handler_t resolver [in]
     */
    http_authentication_resolver& digest_resolver(authenticate_handler_t resolver);
    /*
     * @brief   authenticate
     * @param   http_authenticate_provider* provider [in]
     * @param   network_session* session [in]
     * @param   http_response* response [in]
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool digest_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   register handler
     * @param   authenticate_handler_t resolver [in]
     */
    http_authentication_resolver& bearer_resolver(authenticate_handler_t resolver);
    /*
     * @brief   authenticate
     * @param   http_authenticate_provider* provider [in]
     * @param   network_session* session [in]
     * @param   http_response* response [in]
     * @remarks
     *          RFC6750 The OAuth 2.0 Authorization Framework: Bearer Token Usage
     */
    bool bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

    /**
     * @brief   register handler
     * @param   authenticate_handler_t resolver [in]
     */
    http_authentication_resolver& custom_resolver(authenticate_handler_t resolver);
    /*
     * @brief   authenticate
     * @param   http_authenticate_provider* provider [in]
     * @param   http_response* response [in]
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool custom_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

    basic_credentials& get_basic_credentials(std::string const& realm);
    digest_credentials& get_digest_credentials(std::string const& realm);
    bearer_credentials& get_bearer_credentials(std::string const& realm);
    oauth2_credentials& get_oauth2_credentials();
    custom_credentials& get_custom_credentials();

   private:
    authenticate_handler_t _basic_resolver;
    authenticate_handler_t _digest_resolver;
    authenticate_handler_t _bearer_resolver;
    authenticate_handler_t _custom_resolver;

    typedef std::map<std::string, basic_credentials> realm_basic_credentials_t;
    typedef std::map<std::string, digest_credentials> realm_digest_credentials_t;
    typedef std::map<std::string, bearer_credentials> realm_bearer_credentials_t;
    typedef std::pair<realm_basic_credentials_t::iterator, bool> realm_basic_credentials_pib_t;
    typedef std::pair<realm_digest_credentials_t::iterator, bool> realm_digest_credentials_pib_t;
    typedef std::pair<realm_bearer_credentials_t::iterator, bool> realm_bearer_credentials_pib_t;

    realm_basic_credentials_t _realm_basic_credentials;    // map<realm, credentials>
    realm_digest_credentials_t _realm_digest_credentials;  // map<realm, credentials>
    realm_bearer_credentials_t _realm_bearer_credentials;  // map<realm, credentials>
    oauth2_credentials _oauth2_credentials;
    custom_credentials _custom_credentials;
};

}  // namespace net
}  // namespace hotplace

#endif
