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

#ifndef __HOTPLACE_SDK_NET_HTTP_DIGEST_ACCESS_AUTHENTICATION_PROVIDER__
#define __HOTPLACE_SDK_NET_HTTP_DIGEST_ACCESS_AUTHENTICATION_PROVIDER__

#include <map>
#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/types.hpp>
#include <string>

namespace hotplace {
namespace net {

/**
 * @brief   digest
 *          RFC 2069 An Extension to HTTP : Digest Access Authentication
 *          RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *
 *          Server
 *              WWW-Authenticate: Digest realm="digest realm", qop="auth, auth-int",
 *                                       nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"
 *
 *          Client
 *              Authorization: Digest username="test",
 *                             realm="Protected",
 *                             nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
 *                             uri="/login",
 *                             response="dc17f5db4addad1490b3f565064c3621",
 *                             opaque="5ccc069c403ebaf9f0171e9517f40e41",
 *                             qop=auth, nc=00000001, cnonce="3ceef920aacfb49e"
 */
class digest_access_authentication_provider : public http_authentication_provider {
   public:
    /**
     * @brief   constructor
     * @param   const char* realm [in]
     */
    digest_access_authentication_provider(const std::string& realm);
    digest_access_authentication_provider(const std::string& realm, const char* algorithm, const char* qop, bool userhash = false);
    digest_access_authentication_provider(const std::string& realm, const std::string& algorithm, const std::string& qop, bool userhash = false);
    virtual ~digest_access_authentication_provider();

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

    /**
     * @brief   compare opaque
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @param   skey_value& kv [inout]
     */
    return_t prepare_digest_access(network_session* session, http_request* request, http_response* response, skey_value& kv);
    /**
     * @brief   digest
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @param   skey_value& kv [inout]
     */
    return_t auth_digest_access(network_session* session, http_request* request, http_response* response, skey_value& kv);

    /**
     * @brief   algorithm
     * @param   const char* algorithm [in] "MD5", "MD5-sess", "SHA-256", "SHA-256-sess" (tested - chrome, edge)
     *                                     "SHA-512-256", "SHA-512-256-sess"
     */
    digest_access_authentication_provider& set_algorithm(const char* algorithm);
    /**
     * @brief   quality of protection, "auth" authentication/"auth-int" authentication with integrity protection
     * @param   const char* qop [inopt] "auth, auth-int", "auth-int, auth", "auth", "auth-int"
     */
    digest_access_authentication_provider& set_qop(const char* qop);
    /**
     * @brief   userhash
     * @param   bool enable [in]
     * @remarks RFC7616 HTTP Digest Access Authentication
     */
    digest_access_authentication_provider& set_userhash(bool enable);

    std::string get_algorithm();
    std::string get_qop();
    bool get_userhash();

   private:
    std::string _algorithm;
    std::string _qop;
    bool _userhash;
};

}  // namespace net
}  // namespace hotplace

#endif
