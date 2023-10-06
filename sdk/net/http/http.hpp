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

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/base/stream/buffer_stream.hpp>
#include <hotplace/sdk/net/server/network_protocol.hpp>
#include <map>

namespace hotplace {
namespace net {

class http_header
{
public:
    http_header ();
    virtual ~http_header ();

    /**
     * @brief add a header
     * @param   const char*     header      [IN]
     * @param   const char*     value       [IN]
     * @return error code (see error.hpp)
     * @remarks
     *          header.add ("WWW-Authenticate", "Basic realm=\"protected\"");
     */
    return_t add (const char* header, const char* value);

    /**
     * @brief add a header
     * @param   std::string     header      [IN]
     * @param   std::string     value       [IN]
     * @return error code (see error.hpp)
     */
    return_t add (std::string header, std::string value);

    return_t clear ();

    /**
     * @brief read a header
     * @param   const char*     header      [IN]
     * @remarks
     *          header.get ("Content-Length", conent_length);
     */
    const char* get (const char* header, std::string& content);
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
    const char* get_token (const char* header, unsigned index, std::string& token);

    /**
     * @brief read all headers
     * @return error code (see error.hpp)
     */
    return_t get_headers (std::string& contents);

protected:
    typedef std::map<std::string, std::string> http_header_map_t;
    typedef std::pair<http_header_map_t::iterator, bool> http_header_map_pib_t;
    http_header_map_t _headers;
    critical_section _lock;
};

class http_request;
class http_uri
{
public:
    http_uri ();
    ~http_uri ();

    /**
     * @brief open
     * @param std::string url [in]
     */
    return_t open (std::string url);
    return_t open (const char* url);
    /**
     * @brief close
     */
    void close ();

    /**
     * @brief url
     */
    const char* get_url ();
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
    return_t query (unsigned index, std::string& key, std::string& value);
    /**
     * @brief read a param
     * @return error code (see error.hpp)
     */
    return_t query (std::string key, std::string& value);
    /**
     * @brief count of query
     * @remarks
     */
    size_t countof_query ();

    void addref ();
    void release ();

protected:
    std::string _url;

    typedef std::map<std::string, std::string> PARAMETERS;
    PARAMETERS _query;

    t_shared_reference <http_uri> _shared;
};

class http_request
{
public:
    http_request ();
    virtual ~http_request ();

    /**
     * @brief open
     * @param   const char*     request         [IN]
     * @param   size_t          size_request    [IN]
     * @return error code (see error.hpp)
     */
    return_t open (const char* request, size_t size_request);
    /**
     * @brief close
     * @return error code (see error.hpp)
     */
    return_t close ();

    /**
     * @brief return the http_header object
     */
    http_header* get_header ();
    /**
     * @brief return the http_uri object
     */
    http_uri* get_uri ();
    /**
     * @brief url
     */
    const char* get_url ();
    /**
     * @brief return the method (GET, POST, ...)
     */
    const char* get_method ();
    /**
     * @brief return the request
     */
    const char* get_request ();

protected:

    std::string _method;
    std::string _request;

    http_header __header;
    http_uri __uri;
};

class http_response
{
public:
    http_response ();
    ~http_response ();

    return_t compose (const char* content_type, const char* content, int status_code);
    const char* content_type ();
    const char* content ();
    size_t content_size ();
    int status_code ();

protected:
    std::string _content_type;
    std::string _content;
    int _statuscode;
};

class http_authenticate_provider
{
public:
    http_authenticate_provider ()
    {
    }

    virtual return_t authenticate (network_session * session, http_request* request, http_response) = 0;
};

/**
 * @brief   basic
 *          RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 *
 *          Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 */
class http_basic_authenticate_provider : public http_authenticate_provider
{
public:
    http_basic_authenticate_provider ();
    virtual ~http_basic_authenticate_provider ();

    virtual return_t authenticate (network_session * session, http_request* request, http_response);
};

/**
 * @brief   digest
 *          RFC 2069 An Extension to HTTP : Digest Access Authentication
 *          RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 * input
 *     Authorization: Digest username="test",
 *                      realm="Protected",
 *                      nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
 *                      uri="/login",
 *                      response="dc17f5db4addad1490b3f565064c3621",
 *                      opaque="5ccc069c403ebaf9f0171e9517f40e41",
 *                      qop=auth, nc=00000001, cnonce="3ceef920aacfb49e"
 *
 * output
 *     username=test
 *     realm=Protected
 *     nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093
 *     uri=/login
 *     response=dc17f5db4addad1490b3f565064c3621
 *     opaque=5ccc069c403ebaf9f0171e9517f40e41
 *     qop=auth
 *     nc=00000001
 *     cnonce=3ceef920aacfb49e
 */
class http_digest_access_authenticate_provider : public http_authenticate_provider
{
public:
    http_digest_access_authenticate_provider ();
    virtual ~http_digest_access_authenticate_provider ();

    virtual return_t authenticate (network_session * session, http_request* request, http_response);
};

class http_bearer_authenticate_provider : public http_authenticate_provider
{
public:
    http_bearer_authenticate_provider ();
    virtual ~http_bearer_authenticate_provider ();

    virtual return_t authenticate (network_session * session, http_request* request, http_response);
};

class http_authenticate_store
{
public:
    http_authenticate_store ();
    ~http_authenticate_store ();

    http_authenticate_store& operator << (http_authenticate_provider* provider);

protected:
    critical_section _lock;
    std::list <http_authenticate_provider*> _list;
};

class http_authenticate_resolver
{
public:
    http_authenticate_resolver ();
    virtual ~http_authenticate_resolver ();

    virtual return_t resolve (http_authenticate_store* store, network_session* session, http_request* request);
};

class http_handler
{
public:
    http_handler (const char* uri, http_authenticate_store* auth = nullptr);
    virtual return_t service_handler (network_session* session, http_request* request, http_response* response, uint16& status_code);
    virtual return_t auth_handler (network_session* session, http_request* request, http_response* response, uint16& status_code);

    virtual int addref ();
    virtual int release ();

private:
    http_authenticate_store* auth_store;
    t_shared_reference <http_handler> _instance;
};

class http_handler_dispatcher
{
public:
    http_handler_dispatcher ();

    http_handler_dispatcher& add (http_handler* handler);
private:
    typedef std::map <std::string, http_handler*> handler_map_t;
    handler_map_t _handler_map;
};

class http_server
{
public:
    http_server ();
    ~http_server ();

protected:
    static return_t network_routine (uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context);
    static return_t accept_control_handler (socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter);
};

}
}  // namespace

#endif
