/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * Basic Authentication
 * Digest Access Authentication
 *      algorithm=MD5
 *      algorithm=MD5-sess
 *      algorithm=SHA-256
 *      algorithm=SHA-256-sess
 *      qop=auth
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_HTTP__
#define __HOTPLACE_SDK_NET_SERVER_HTTP__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/net/server/network_protocol.hpp>

namespace hotplace {
using namespace io;
namespace net {

class http_header {
   public:
    http_header();
    virtual ~http_header();

    /**
     * @brief  add a header
     * @param  const char*     header      [IN]
     * @param  const char*     value       [IN]
     * @return *this
     * @remarks
     *          header.add ("WWW-Authenticate", "Basic realm=\"protected\"");
     */
    http_header& add(const char* header, const char* value);

    /**
     * @brief  add a header
     * @param  std::string     header      [IN]
     * @param  std::string     value       [IN]
     * @return *this
     */
    http_header& add(std::string header, std::string value);

    /**
     * @brief  clear
     * @return *this
     */
    http_header& clear();

    /**
     * @brief   conversion
     * @param   std::string const& value [in]
     * @param   key_value& kv [out]
     * @return  error code (see error.hpp)
     * @sample
     *          const char* auth =
     *              "Digest username=\"user\", realm=\"happiness\", nonce=\"b10d9755f22e0cc887d3b195569dca7a\", uri=\"/auth/digest\", "
     *              "response=\"756ae055c932efce3d1f1a38129aab3b\", opaque=\"553c454bedbdc9bb352df88630663669\", qop=auth, nc=00000002, "
     *              "cnonce=\"f3806458ed81c203\"";
     *
     *          http_header::to_keyvalue(auth, kv);
     *          const char* nonce = kv.get("nonce");
     *          const char* uri = kv.get("uri");
     *          const char* response = kv.get("response");
     *          const char* opaque = kv.get("opaque");
     *          const char* qop = kv.get("qop");
     *          const char* nc = kv.get("nc");
     *          const char* cnonce = kv.get("cnonce");
     */
    static return_t to_keyvalue(std::string const& value, key_value& kv);

    /**
     * @brief read a header
     * @param   const char* header [in]
     * @param   std::string& content [out]
     * @return  value
     * @sample
     *          header.get ("Content-Length", conent_length);
     */
    const char* get(const char* header, std::string& content);
    /**
     * @brief   read a header token
     * @param   const char* header [in]
     * @param   unsigned index [in]
     * @param   std::string& token [out]
     * @return  token
     * @sample
     *          // Authorization: Bearer 0123-4567-89ab-cdef
     *          header.get ("Authorization", 0, auth_type); // Bearer
     *          header.get ("Authorization", 1, auth_data); // 0123-4567-89ab-cdef
     *          if (auth_type == "Basic") ...
     *          else if (auth_type == "Digest") ...
     */
    const char* get_token(const char* header, unsigned index, std::string& token);

    /**
     * @brief read all headers
     * @param std::string& contents [out]
     * @return error code (see error.hpp)
     */
    return_t get_headers(std::string& contents);

   protected:
    typedef std::map<std::string, std::string> http_header_map_t;
    typedef std::pair<http_header_map_t::iterator, bool> http_header_map_pib_t;
    http_header_map_t _headers;
    critical_section _lock;
};

class http_request;
class http_uri {
   public:
    http_uri();
    ~http_uri();

    /**
     * @brief open
     * @param std::string uri [in]
     * @return error code (see error.hpp)
     */
    return_t open(std::string uri);
    return_t open(const char* uri);
    /**
     * @brief close
     */
    void close();

    /**
     * @brief URI
     */
    const char* get_uri();
    /**
     * @brief query
     * @param   unsigned        index       [IN] 0 <= index < size_parameter ()
     * @param   std::string&    key         [OUT]
     * @param   std::string&    value       [OUT]
     * @return error code (see error.hpp)
     * @remarks
     *          http_uri url ("/resource/entity?spec=full&period=week")
     *          url.query (0, key, value) return spec and full
     *          url.query (1, key, value) return period and week
     */
    return_t query(unsigned index, std::string& key, std::string& value);
    /**
     * @brief read a param
     * @param std::string key [in]
     * @param std::string& value [out]
     * @return error code (see error.hpp)
     */
    return_t query(std::string key, std::string& value);
    /**
     * @brief count of query
     * @remarks
     */
    size_t countof_query();

    void addref();
    void release();

   protected:
    std::string _url;

    typedef std::map<std::string, std::string> PARAMETERS;
    PARAMETERS _query;

    t_shared_reference<http_uri> _shared;
};

class http_request {
   public:
    http_request();
    virtual ~http_request();

    /**
     * @brief  open
     * @param  const char*     request         [IN]
     * @param  size_t          size_request    [IN]
     * @return error code (see error.hpp)
     */
    return_t open(const char* request, size_t size_request);
    return_t open(std::string const& request);
    /**
     * @brief  close
     * @return error code (see error.hpp)
     */
    return_t close();

    /**
     * @brief return the http_header object
     */
    http_header& get_header();
    /**
     * @brief return the http_uri object
     */
    http_uri& get_http_uri();
    /**
     * @brief url
     */
    const char* get_uri();
    /**
     * @brief return the method (GET, POST, ...)
     */
    const char* get_method();
    /**
     * @brief content
     */
    std::string get_content();

    http_request& get_request(basic_stream& bs);

   protected:
    std::string _method;
    std::string _content;

    http_header _header;
    http_uri _uri;
};

class http_response {
   public:
    http_response();
    http_response(http_request* request);
    ~http_response();

    /* *
     * @brief  open
     * @param  const char*     response        [IN]
     * @param  size_t          size_response   [IN]
     * @return error code (see error.hpp)
     */
    return_t open(const char* response, size_t size_response);
    return_t open(std::string const& response);
    /* *
     * @brief  close
     * @return error code (see error.hpp)
     */
    return_t close();

    http_response& compose(int status_code);
    http_response& compose(int status_code, const char* content_type, const char* content, ...);
    const char* content_type();
    const char* content();
    size_t content_size();
    int status_code();
    http_header& get_header();
    http_request* get_request();

    http_response& get_response(basic_stream& bs);

   protected:
    http_request* _request;
    http_header _header;
    std::string _content_type;
    std::string _content;
    int _statuscode;
};

class http_resource {
   public:
    static http_resource* get_instance();

    std::string load(int status);

   protected:
    http_resource();

    static http_resource _instance;
    std::map<int, std::string> _status_codes;
};

class http_authenticate_resolver;

class http_authenticate_provider {
   public:
    http_authenticate_provider(std::string const& realm) : _realm(realm) { _shared.make_share(this); }

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response) = 0;
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response) = 0;

    virtual std::string get_challenge(http_request* request) {
        std::string token_auth;
        constexpr char constexpr_authorization[] = "Authorization";
        request->get_header().get(constexpr_authorization, token_auth);
        return token_auth;
    }
    virtual int addref() { return _shared.addref(); }
    virtual int release() { return _shared.delref(); }

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

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response);
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
    rfc2617_digest& clear();

   private:
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

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response);
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
    return_t digest_digest_access(network_session* session, http_request* request, http_response* response, key_value& kv);

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

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request, http_response* response);
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);
};

typedef std::function<bool(http_authenticate_provider*, network_session*, http_request* request, http_response* response)> authenticate_handler_t;
class http_authenticate_resolver {
   public:
    http_authenticate_resolver();

    /**
     * @brief resolve
     * @param http_authenticate_provider* provider [in]
     * @param network_session* session [in]
     * @param http_request* request [in]
     * @param http_response* response [in]
     * @return error code (see error.hpp)
     */
    return_t resolve(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

    /**
     * @brief register resolver
     * @param authenticate_handler_t resolver [in]
     */
    http_authenticate_resolver& basic_resolver(authenticate_handler_t resolver);
    /*
     * @brief authenticate
     * @param http_authenticate_provider* provider [in]
     * @param http_response* response [in]
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool basic_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);
    http_authenticate_resolver& digest_resolver(authenticate_handler_t resolver);
    /*
     * @brief authenticate
     * @param http_authenticate_provider* provider [in]
     * @param network_session* session [in]
     * @param http_response* response [in]
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool digest_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);
    http_authenticate_resolver& bearer_resolver(authenticate_handler_t resolver);
    /*
     * @brief authenticate
     * @param http_authenticate_provider* provider [in]
     * @param network_session* session [in]
     * @param http_response* response [in]
     * @remarks
     *          RFC6750 The OAuth 2.0 Authorization Framework: Bearer Token Usage
     */
    bool bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

   private:
    authenticate_handler_t _basic_resolver;
    authenticate_handler_t _digest_resolver;
    authenticate_handler_t _bearer_resolver;
};

typedef void (*http_request_handler_t)(http_request*, http_response*);
typedef std::function<void(http_request*, http_response*)> http_request_function_t;

class http_router {
   public:
    http_router();
    ~http_router();

    http_router& add(const char* uri, http_request_handler_t handler);
    http_router& add(const char* uri, http_request_function_t handler);
    http_router& add(const char* uri, http_authenticate_provider* handler);

    return_t route(const char* uri, network_session* session, http_request* request, http_response* response);

    http_authenticate_resolver& get_authenticate_resolver();

   protected:
    bool try_auth(const char* uri, http_request* request, http_response* response, http_authenticate_provider** provider);

   private:
    void clear();

    typedef struct _http_router_t {
        http_request_handler_t handler;
        http_request_function_t stdfunc;

        _http_router_t() : handler(nullptr), stdfunc(nullptr) {}
    } http_router_t;
    typedef std::map<std::string, http_router_t> handler_map_t;
    typedef std::map<std::string, http_authenticate_provider*> authenticate_map_t;
    typedef std::pair<authenticate_map_t::iterator, bool> authenticate_map_pib_t;

    critical_section _lock;
    handler_map_t _handler_map;
    authenticate_map_t _authenticate_map;
    http_authenticate_resolver _resolver;
};

}  // namespace net
}  // namespace hotplace

#endif
