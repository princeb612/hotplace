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

#ifndef __HOTPLACE_SDK_NET_HTTP_AUTHENTICATE__
#define __HOTPLACE_SDK_NET_HTTP_AUTHENTICATE__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/net/http/http.hpp>
#include <sdk/net/server/network_protocol.hpp>

namespace hotplace {
using namespace io;
namespace net {

class http_authenticate_resolver;

/**
 * @brief   authentication
 * @sample
 *          // sketch
 *          bool xxx_provider::try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request,
 *                                                      http_response* response) {
 *              ...
 *              ret_value  = resolver->xxx_authenticate(this, session, request, response);
 *              if (false == ret_value) {
 *                  do not call resolver->request_auth // after request_auth, session data change
 *              }
 *          }
 */
class http_authenticate_provider {
   public:
    http_authenticate_provider(std::string const& realm) : _realm(realm) { _shared.make_share(this); }

    /**
     * @brief   try
     * @param   http_authenticate_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response) = 0;
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
    virtual std::string get_challenge(http_request* request) {
        std::string token_auth;
        constexpr char constexpr_authorization[] = "Authorization";
        request->get_http_header().get(constexpr_authorization, token_auth);
        return token_auth;
    }

    virtual int addref() { return _shared.addref(); }
    virtual int release() { return _shared.delref(); }

    /**
     * @brief   realm
     */
    std::string get_realm() { return _realm; }

   protected:
    t_shared_reference<http_authenticate_provider> _shared;
    std::string _realm;
};

/**
 * @brief   basic
 *          RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *
 *          Server
 *              WWW-Authenticate: Basic realm="basic realm"
 *          Client
 *              Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 */
class http_basic_authenticate_provider : public http_authenticate_provider {
   public:
    http_basic_authenticate_provider(const char* realm);
    virtual ~http_basic_authenticate_provider();

    /**
     * @brief   try
     * @param   http_authenticate_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   401 Unauthorized
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);
};

class rfc2617_digest {
   public:
    rfc2617_digest();
    rfc2617_digest& add(const char* data);
    rfc2617_digest& add(std::string const& data);
    rfc2617_digest& add(basic_stream const& data);
    rfc2617_digest& operator<<(const char* data);
    rfc2617_digest& operator<<(std::string const& data);
    rfc2617_digest& operator<<(basic_stream const& data);
    rfc2617_digest& digest(std::string const& algorithm);
    std::string get();
    std::string get_sequence();
    rfc2617_digest& clear();

   private:
    basic_stream _sequence;
    basic_stream _stream;
};

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
class http_digest_access_authenticate_provider : public http_authenticate_provider {
   public:
    /**
     * @brief   constructor
     * @param   const char* realm [in]
     */
    http_digest_access_authenticate_provider(const char* realm);
    http_digest_access_authenticate_provider(const char* realm, const char* algorithm, const char* qop, bool userhash = false);
    virtual ~http_digest_access_authenticate_provider();

    /**
     * @brief   try
     * @param   http_authenticate_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response);
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
     * @param   key_value& kv [inout]
     */
    return_t prepare_digest_access(network_session* session, http_request* request, http_response* response, key_value& kv);
    /**
     * @brief   digest
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @param   key_value& kv [inout]
     */
    return_t auth_digest_access(network_session* session, http_request* request, http_response* response, key_value& kv);

    /**
     * @brief   algorithm
     * @param   const char* algorithm [in] "MD5", "MD5-sess", "SHA-256", "SHA-256-sess" (tested - chrome, edge)
     *                                     "SHA-512-256", "SHA-512-256-sess"
     */
    http_digest_access_authenticate_provider& set_algorithm(const char* algorithm);
    /**
     * @brief   quality of protection, "auth" authentication/"auth-int" authentication with integrity protection
     * @param   const char* qop [inopt] "auth, auth-int", "auth-int, auth", "auth", "auth-int"
     */
    http_digest_access_authenticate_provider& set_qop(const char* qop);
    /**
     * @brief   userhash
     * @param   bool enable [in]
     * @remarks RFC7616 HTTP Digest Access Authentication
     */
    http_digest_access_authenticate_provider& set_userhash(bool enable);

    std::string get_algorithm();
    std::string get_qop();
    bool get_userhash();

   private:
    std::string _algorithm;
    std::string _qop;
    bool _userhash;
};

class http_bearer_authenticate_provider : public http_authenticate_provider {
   public:
    http_bearer_authenticate_provider(const char* realm);
    virtual ~http_bearer_authenticate_provider();

    /**
     * @brief   try
     * @param   http_authenticate_resolver* resolver [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @return  error code (see error.hpp)
     */
    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response);
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

typedef std::function<bool(http_authenticate_provider*, network_session*, http_request* request, http_response* response)> authenticate_handler_t;
class http_authenticate_resolver {
   public:
    http_authenticate_resolver();

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
    http_authenticate_resolver& basic_resolver(authenticate_handler_t handler);
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
    http_authenticate_resolver& digest_resolver(authenticate_handler_t handler);
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
    http_authenticate_resolver& bearer_resolver(authenticate_handler_t handler);
    /*
     * @brief   authenticate
     * @param   http_authenticate_provider* provider [in]
     * @param   network_session* session [in]
     * @param   http_response* response [in]
     * @remarks
     *          RFC6750 The OAuth 2.0 Authorization Framework: Bearer Token Usage
     */
    bool bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

   private:
    authenticate_handler_t _basic_resolver;
    authenticate_handler_t _digest_resolver;
    authenticate_handler_t _bearer_resolver;
};

}  // namespace net
}  // namespace hotplace

#endif
