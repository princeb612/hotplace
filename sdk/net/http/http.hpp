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

#ifndef __HOTPLACE_SDK_NET_HTTP__
#define __HOTPLACE_SDK_NET_HTTP__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/tls/tls_client.hpp>

namespace hotplace {
using namespace io;
namespace net {

enum http_method_t {
    HTTP_OPTIONS = 1,
    HTTP_GET = 2,
    HTTP_HEAD = 3,
    HTTP_POST = 4,
    HTTP_PUT = 5,
    HTTP_DELETE = 6,
    HTTP_TRACE = 7,
};

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
     * @param   std::string& value [out]
     * @return  value
     * @sample
     *          header.get ("Content-Length", conent_length);
     */
    const char* get(const char* header, std::string& value);
    std::string get(const char* header);
    bool contains(const char* header, const char* value);
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
    const char* get_query();
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
    std::string _uri;
    std::string _query;

    typedef std::map<std::string, std::string> PARAMETERS;
    PARAMETERS _query_kv;

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
    return_t open(const char* request, size_t size_request, bool optimize = false);
    return_t open(const char* request, bool optimize = false);
    return_t open(basic_stream const& request, bool optimize = false);
    return_t open(std::string const& request, bool optimize = false);
    /**
     * @brief  close
     * @return error code (see error.hpp)
     */
    return_t close();

    /**
     * @brief return the http_header object
     */
    http_header& get_http_header();
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

    http_request& compose(http_method_t method, std::string const& uri, std::string const& body);
    http_request& get_request(basic_stream& stream);

    void addref();
    void release();

   protected:
    t_shared_reference<http_request> _shared;

   private:
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
    return_t open(const char* response);
    return_t open(basic_stream const& response);
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
    http_header& get_http_header();
    http_request* get_http_request();

    http_response& get_response(basic_stream& bs);

    void addref();
    void release();

   protected:
    t_shared_reference<http_response> _shared;

   private:
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
    std::string get_method(http_method_t method);

   protected:
    http_resource();

    static http_resource _instance;
    std::map<int, std::string> _status_codes;
    std::map<http_method_t, std::string> _methods;
};

/**
 * @brief   simple client
 * @sample
 *      // sketch
 *
 *      http_client client;
 *      http_response* response = nullptr;
 *      client.request("https://localhost:9000/", &response); // connect, send, read
 *      // ...
 *      resposne->release();
 *
 *      http_request request;
 *      request.compose(GET, "/");
 *      request.get_http_header().add("Accept-Encoding", "gzip, deflate");
 *      client.request(request, &response);
 *      // ...
 *      response->release();
 */
class http_client {
   public:
    http_client();
    ~http_client();

    client_socket* connect(std::string const& url);
    client_socket* connect(url_info_t const& url_info);
    http_client& request(std::string const& url, http_response** response);
    http_client& request(http_request& request, http_response** response);
    http_client& close();

   protected:
    http_client& request_and_response(url_info_t const& url_info, http_request& request, http_response** response);

   private:
    socket_t _socket;
    client_socket* _client_socket;
    transport_layer_security_client* _tls_client_socket;
    tls_context_t* _tls_context;
    SSL_CTX* _x509;
    url_info_t _url_info;
};

}  // namespace net
}  // namespace hotplace

#endif
