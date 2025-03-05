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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPAUTHENTICATIONPROVIDER__
#define __HOTPLACE_SDK_NET_HTTP_HTTPAUTHENTICATIONPROVIDER__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   authentication
 * @sample
 *          // sketch
 *          bool xxx_provider::try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request,
 *                                                      http_response* response) {
 *              ...
 *              ret_value  = resolver->xxx_authenticate(this, session, request, response);
 *              if (false == ret_value) {
 *                  do not call resolver->request_auth // after request_auth, session data change
 *              }
 *          }
 */
class http_authentication_provider {
   public:
    http_authentication_provider(const std::string& realm);

    /**
     * @brief   try
     * @param   http_authentication_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authentication_resolver* resolver, network_session* session, http_request* request, http_response* response) = 0;
    /**
     * @brief   401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response) = 0;
    /**
     * @brief   challenge
     * @param   http_request* request [in]
     */
    virtual std::string get_challenge(http_request* request);

    virtual int addref();
    virtual int release();

    /**
     * @brief   realm
     */
    const std::string& get_realm() const;

   protected:
   private:
    t_shared_reference<http_authentication_provider> _shared;
    std::string _realm;
};

}  // namespace net
}  // namespace hotplace

#endif
