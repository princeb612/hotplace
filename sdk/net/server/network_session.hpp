/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          OVERLAPPED
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKSESSION__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKSESSION__

#include <sdk/io.hpp>
#include <sdk/net/basic/tcp_server_socket.hpp>
#include <sdk/net/basic/udp_server_socket.hpp>
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http2/http2_session.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/server/network_stream.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

struct network_session_buffer_t {
#if defined __linux__
    char* buffer;
    size_t buflen;
#elif defined _WIN32 || defined _WIN64
    /* windows overlapped */
    // assign per socket
    OVERLAPPED overlapped;
    WSABUF wsabuf;
#endif

    std::vector<char> bin;
    size_t bufsize;

    network_session_buffer_t() : bufsize(1500) { init(); }
    void init() {
        bin.resize(bufsize);  // do nothing if capacity == size()
#if defined __linux__
        buffer = &bin[0];
        buflen = bin.size();
#elif defined _WIN32 || defined _WIN64
        memset(&overlapped, 0, sizeof(OVERLAPPED));
        wsabuf.len = bin.size();
        wsabuf.buf = &bin[0];
#endif
    }
    void set_bufsize(size_t size) {
        if (size) {
            bufsize = size;
        }
    }
};

/**
 * @sa
 *      network_session::socket_info
 *      network_server netserver_cb_type_t::netserver_cb_socket
 */
struct network_session_socket_t {
    handle_t event_socket;
    sockaddr_storage_t cli_addr;  // both ipv4 and ipv6

    network_session_socket_t() : event_socket((handle_t)INVALID_SOCKET) {}
};

struct network_session_t {
    network_session_socket_t netsock;
    network_session_buffer_t buf;

    void* mplexer_handle;
    server_socket* svr_socket;
    tls_context_t* tls_handle;
    int priority;

    network_session_t() : mplexer_handle(nullptr), svr_socket(nullptr), tls_handle(nullptr), priority(0) {}
    network_session_socket_t* socket_info() { return &netsock; }
    network_session_buffer_t& get_buffer() { return buf; }
};

/**
 * @brief session data
 */
class network_session_data : public t_skey_value<std::string> {
   public:
    network_session_data() {}
    virtual ~network_session_data() {}
};

/**
 * @brief session
 */
class network_session {
    friend class network_server;

   public:
    network_session(server_socket* svr_socket);
    virtual ~network_session();

    /**
     * @brief   connect handler
     * @param   handle_t            event_socket  [IN]
     * @param   sockaddr_storage_t* sockaddr    [IN]
     * @param   tls_context_t*      tls_handle  [IN]
     * @return  error code (see error.hpp)
     * @remarks copy socket and address
     */
    return_t connected(handle_t event_socket, sockaddr_storage_t* sockaddr, tls_context_t* tls_handle);
    /**
     * @brief   handle udp data without cookie secret
     */
    return_t dgram_start(handle_t listen_sock);
    /**
     * @brief in windows call wsarecv to read asynchronously
     * @return  error code (see error.hpp)
     */
    return_t ready_to_read();

    /**
     * @brief send
     * @param const char*         data_ptr        [IN]
     * @param size_t              size_data       [IN]
     * @return  error code (see error.hpp)
     */
    return_t send(const char* data_ptr, size_t size_data);
    return_t send(const byte_t* data_ptr, size_t size_data);
    return_t sendto(const char* data_ptr, size_t size_data, sockaddr_storage_t* addr);
    return_t sendto(const byte_t* data_ptr, size_t size_data, sockaddr_storage_t* addr);

    /**
     * @brief return socket information
     */
    network_session_socket_t* socket_info();
    network_session_buffer_t* get_buffer();

#if defined _WIN32 || defined _WIN64
    /**
     * @brief in windows return wsabuf structure
     */
    WSABUF* wsabuf_read();
#endif
    /**
     * @brief return raw-stream
     */
    network_stream* getstream();
    /**
     * @brief return composed-stream
     */
    network_stream* getrequest();

    /**
     * @brief return priority
     */
    int get_priority();
    /**
     * @brief elevate priority
     * @param   int priority        [IN]
     */
    void set_priority(int priority);

    int addref();
    /**
     * @brief release object if not referenced
     */
    virtual int release();
    /**
     * @brief produce, push into stream
     * @param   t_mlfq<network_session>*    q               [IN]
     * @param   byte_t*                     buf_read        [IN]
     * @param   size_t                      size_buf_read   [IN]
     * @param   const sockaddr_storage_t*   addr            [inopt]
     * @remarks
     */
    return_t produce(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr = nullptr);
    /**
     * @brief consume from stream and put into request, then read stream buffer list from request
     * @param   network_protocol_group* protocol_group              [IN]
     * @param   network_stream_data**   ptr_network_stream_buffer   [OUT] see network_stream::consume
     */
    return_t consume(network_protocol_group* protocol_group, network_stream_data** ptr_network_stream_buffer);

    server_socket* get_server_socket();
    network_session_data* get_session_data();
    http2_session& get_http2_session();

    network_session& trace(std::function<void(stream_t*)> f);

   protected:
    return_t produce_stream(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr = nullptr);
    return_t produce_dgram(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr = nullptr);

    network_session_t _session;
    network_stream _stream;
    network_stream _request;
    network_session_data _session_data;

    http2_session _http2_session;

    std::function<void(stream_t*)> _df;

    t_shared_reference<network_session> _shared;
    critical_section _lock;
};

class server_conf;

/**
 * @brief network_session container
 */
class network_session_manager {
   public:
    network_session_manager();
    ~network_session_manager();

    void set_server_conf(server_conf* conf);
    server_conf* get_server_conf();

    /**
     * @brief   [TCP/TLS] new network_session
     * @param   handle_t            event_socket      [IN]
     * @param   sockaddr_storage_t* sockaddr        [IN]
     * @param   server_socket*      svr_socket      [IN]
     * @param   tls_context_t*      tls_handle      [IN]
     * @param   network_session**   ptr_session_object  [OUT] use release to free
     * @return  error code (see error.hpp)
     */
    return_t connected(handle_t event_socket, sockaddr_storage_t* sockaddr, server_socket* svr_socket, tls_context_t* tls_handle,
                       network_session** ptr_session_object);
    /**
     * @brief   [TCP/TLS] find a network session
     * @param   handle_t            event_socket          [IN]
     * @param   network_session**   ptr_session_object  [OUT] referenced, call release
     * @return  error code (see error.hpp)
     * @example
     *          network_session* session = session_manager.find (event_socket);
     *          if (nullptr != session)
     *          {
     *              session->release (); // decrease reference counter
     *          }
     */
    return_t find(handle_t event_socket, network_session** ptr_session_object);
    /**
     * @brief   [TCP/TLS] operator[socket]
     * @return  error code (see error.hpp)
     * @remarks
     * @example
     *          network_session* session = session_manager[event_socket];
     *          if (nullptr != session)
     *          {
     *              session->release (); // decrease reference counter
     *          }
     */
    network_session* operator[](handle_t event_socket);
    /**
     * @brief   [TCP/TLS] remove from session list
     * @param   handle_t            event_socket          [IN]
     * @param   network_session**   ptr_session_object  [OUT]
     * @return  error code (see error.hpp)
     */
    return_t ready_to_close(handle_t event_socket, network_session** ptr_session_object);

    /**
     * @brief   [UDP] handle udp data without cookie secret
     */
    return_t dgram_start(handle_t listen_sock, server_socket* svr_socket, tls_context_t* tls_handle, network_session** ptr_session_object);
    /**
     * @brief   [DTLS] handle dtls session
     */
    return_t dgram_start_cookie(handle_t listen_sock, const sockaddr_storage_t* sockaddr, server_socket* svr_socket, tls_context_t* tls_handle,
                                network_session** ptr_session_object);
    /**
     * @brief   [DTLS] find DTLS session
     * @remarks
     *          network_session* session_object = nullptr;
     *          ret = session_manager.find(&sa, &session_object); // refcount++
     *          if (errorcode_t::success == ret) {
     *              // do something
     *              session_object->release(); // refcount--
     *          } else {
     *              // do something
     *          }
     */
    return_t dgram_find(const sockaddr_storage_t* sockaddr, network_session** ptr_session_object);

   protected:
    void shutdown();

    typedef std::map<handle_t, network_session*> network_session_map_t;
    typedef std::pair<network_session_map_t::iterator, bool> network_session_map_pib_t;
    typedef std::map<binary_t, network_session*> dgram_session_map_t;
    typedef std::pair<dgram_session_map_t::iterator, bool> dgram_session_map_pib_t;

    critical_section _session_lock;
    network_session_map_t _session_map;
    dgram_session_map_t _dgram_map;
    server_conf* _server_conf;
};

typedef struct network_session_buffer_t net_session_buffer_t;
typedef struct network_session_socket_t net_session_socket_t;
typedef struct network_session_t net_session_t;
typedef network_session_data net_session_data;
typedef network_session net_session;
typedef network_session_manager net_session_manager;

}  // namespace net
}  // namespace hotplace

#endif
