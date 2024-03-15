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
#include <sdk/net/http/http.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/server/network_protocol.hpp>

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
     * @param   authenticate_handler_t handler [in]
     */
    http_authentication_resolver& basic_resolver(authenticate_handler_t handler);
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
     * @param   authenticate_handler_t handler [in]
     */
    http_authentication_resolver& digest_resolver(authenticate_handler_t handler);
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
     * @param   authenticate_handler_t handler [in]
     */
    http_authentication_resolver& bearer_resolver(authenticate_handler_t handler);
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
     * @param   authenticate_handler_t handler [in]
     */
    http_authentication_resolver& oauth2_resolver(authenticate_handler_t handler);
    /*
     * @brief   authenticate
     * @param   http_authenticate_provider* provider [in]
     * @param   network_session* session [in]
     * @param   http_response* response [in]
     * @remarks
     *          RFC6749 OAuth 2.0
     */
    bool oauth2_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

    http_authentication_resolver& basic_credential(std::string const& userid, std::string const& password);
    http_authentication_resolver& basic_credential(std::string const& challenge);
    http_authentication_resolver& digest_access_credential(std::string const& userid, std::string const& password);
    http_authentication_resolver& digest_access_credential(std::string const& realm, std::string const& algorithm, std::string const& userid,
                                                           std::string const& password);
    http_authentication_resolver& bearer_credential(std::string const& client_id, std::string const& access_token);

   private:
    authenticate_handler_t _basic_resolver;
    authenticate_handler_t _digest_resolver;
    authenticate_handler_t _bearer_resolver;
    authenticate_handler_t _oauth2_resolver;

    critical_section _lock;
    std::set<std::string> _basic_credential;                       // set(base64_encode(concat(userid, ":", password)))
    std::map<std::string, std::string> _digest_access_credential;  // map(userid, password)
    std::map<std::string, std::string> _digest_access_userhash;    // map(_H(userid:realm), userid)
    std::map<std::string, std::string> _bearer_credential;         // map(client_id, access_token)
};

}  // namespace net
}  // namespace hotplace

#endif
