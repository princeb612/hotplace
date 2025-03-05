/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_AUTH_BASICAUTHENTICATIONPROVIDER__
#define __HOTPLACE_SDK_NET_HTTP_AUTH_BASICAUTHENTICATIONPROVIDER__

#include <sdk/net/http/http_authentication_provider.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   basic
 *          RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *
 *          Server
 *              WWW-Authenticate: Basic realm="basic realm"
 *          Client
 *              Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 */
class basic_authentication_provider : public http_authentication_provider {
   public:
    basic_authentication_provider(const std::string& realm);
    virtual ~basic_authentication_provider();

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
     * @brief   401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);
};

}  // namespace net
}  // namespace hotplace

#endif
