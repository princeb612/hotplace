/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
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
     * @brief add a header
     * @param   const char*     header      [IN]
     * @param   const char*     value       [IN]
     * @return error code (see error.hpp)
     * @remarks
     *          header.add ("WWW-Authenticate", "Basic realm=\"protected\"");
     */
    return_t add(const char* header, const char* value);

    /**
     * @brief add a header
     * @param   std::string     header      [IN]
     * @param   std::string     value       [IN]
     * @return error code (see error.hpp)
     */
    return_t add(std::string header, std::string value);

    return_t clear();

    static return_t to_keyvalue(std::string const& value, key_value& kv);

    /**
     * @brief read a header
     * @param   const char*     header      [IN]
     * @remarks
     *          header.get ("Content-Length", conent_length);
     */
    const char* get(const char* header, std::string& content);
    /**
     * @brief read a header token
     * @param   const char*     header      [IN]
     * @remarks
     *          // Authorization: Bearer 0123-4567-89ab-cdef
     *          header.get ("Authorization", 0, auth_type); // Bearer
     *          header.get ("Authorization", 1, auth_data); // 0123-4567-89ab-cdef
     *          if (auth_type == "Basic") ...
     *          else if (auth_type == "Digest") ...
     */
    const char* get_token(const char* header, unsigned index, std::string& token);

    /**
     * @brief read all headers
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
     * @param std::string url [in]
     */
    return_t open(std::string url);
    return_t open(const char* url);
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
     * @brief open
     * @param   const char*     request         [IN]
     * @param   size_t          size_request    [IN]
     * @return error code (see error.hpp)
     */
    return_t open(const char* request, size_t size_request);
    return_t open(std::string const& request);
    /**
     * @brief close
     * @return error code (see error.hpp)
     */
    return_t close();

    /**
     * @brief return the http_header object
     */
    http_header* get_header();
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
     * @brief return the request
     */
    const char* get_request();

    http_request& get_request(basic_stream& bs);

   protected:
    std::string _method;
    std::string _request;

    http_header _header;
    http_uri _uri;
};

class http_response {
   public:
    http_response();
    http_response(http_request* request);
    ~http_response();

    /**
     * @brief open
     * @param   const char*     response        [IN]
     * @param   size_t          size_response   [IN]
     * @return error code (see error.hpp)
     */
    return_t open(const char* response, size_t size_response);
    return_t open(std::string const& response);
    /**
     * @brief close
     * @return error code (see error.hpp)
     */
    return_t close();

    http_response& compose(int status_code);
    http_response& compose(int status_code, const char* content_type, const char* content, ...);
    const char* content_type();
    const char* content();
    size_t content_size();
    int status_code();
    http_header* get_header();
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

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request) = 0;
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response) = 0;

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
 *          Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 */
class http_basic_authenticate_provider : public http_authenticate_provider {
   public:
    http_basic_authenticate_provider(const char* realm);
    virtual ~http_basic_authenticate_provider();

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request);
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);
};

/**
 * @brief   digest
 *          RFC 2069 An Extension to HTTP : Digest Access Authentication
 *          RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *
 *     Authorization: Digest username="test",
 *                      realm="Protected",
 *                      nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
 *                      uri="/login",
 *                      response="dc17f5db4addad1490b3f565064c3621",
 *                      opaque="5ccc069c403ebaf9f0171e9517f40e41",
 *                      qop=auth, nc=00000001, cnonce="3ceef920aacfb49e"
 */
class http_digest_access_authenticate_provider : public http_authenticate_provider {
   public:
    http_digest_access_authenticate_provider(const char* realm);
    virtual ~http_digest_access_authenticate_provider();

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request);
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);
};

class http_bearer_authenticate_provider : public http_authenticate_provider {
   public:
    http_bearer_authenticate_provider(const char* realm);
    virtual ~http_bearer_authenticate_provider();

    virtual bool try_auth(http_authenticate_resolver* resolver, network_session* session, http_request* request);
    virtual return_t request_auth(network_session* session, http_request* request, http_response* response);
};

typedef std::function<bool(http_authenticate_provider*, network_session*, http_request* request, std::string const&)> authenticate_handler_t;
class http_authenticate_resolver {
   public:
    http_authenticate_resolver();

    return_t resolve(http_authenticate_provider* provider, network_session* session, http_request* request, http_response* response);

    http_authenticate_resolver& basic_resolver(authenticate_handler_t resolver);
    /*
     * @brief authenticate
     * @param http_authenticate_provider* provider [in]
     * @param std::string& auth [in] value part of Authorization:
     *          Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool basic_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, std::string const& auth);
    http_authenticate_resolver& digest_resolver(authenticate_handler_t resolver);
    /*
     * @brief authenticate
     * @param http_authenticate_provider* provider [in]
     * @param network_session* session [in]
     * @param std::string& auth [in] value part of Authorization:
     *          Digest username="user", realm="happiness", nonce="a9eefad1e3c288129cdde56480e005f54d", uri="/auth/digest",
     *          response="e1f3fd3e8e93c45acb335c70f4dad6e8", opaque="d2dd1b1eb1fe427defea79899f254c0c", qop=auth, nc=00000002, cnonce="373821d390eaba64"
     * @remarks
     *          RFC2617 HTTP Authentication: Basic and Digest Access Authentication
     */
    bool digest_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, std::string const& auth);
    http_authenticate_resolver& bearer_resolver(authenticate_handler_t resolver);
    /*
     * @brief authenticate
     * @param http_authenticate_provider* provider [in]
     * @param network_session* session [in]
     * @param std::string& auth [in] value part of Authorization:
     * @remarks
     *          RFC6750 The OAuth 2.0 Authorization Framework: Bearer Token Usage
     */
    bool bearer_authenticate(http_authenticate_provider* provider, network_session* session, http_request* request, std::string const& auth);

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
