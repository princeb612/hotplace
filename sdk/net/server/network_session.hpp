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

#include <hotplace/sdk/io/basic/mlfq.hpp>
#include <hotplace/sdk/net/basic/types.hpp>
#include <hotplace/sdk/net/http/http2/http2_session.hpp>  // http2_session
#include <hotplace/sdk/net/server/network_stream.hpp>     // network_stream

namespace hotplace {
namespace net {

/**
 * @brief session data
 */
class network_session_data : public skey_value {
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
    /**
     * @brief   constructor
     * @param   server_socket* svr_socket [in]
     * @param   const sockaddr_storage_t* addr [inopt]
     * @remarks
     *          // dgram_session is bound to listenfd
     *          session_manager.get_dgram_session(&dgram_session, listenfd, ...);
     *          const auto& addr = dgram_session->socket_info()->cli_addr;
     *
     *          // dtls_session is bound to addr
     *          session_manager.get_dgram_cookie_session(&dtls_session, listenfd, &addr, ...);
     */
    network_session(server_socket* svr_socket, const sockaddr_storage_t* addr = nullptr);
    virtual ~network_session();

    /**
     * @brief   connect handler
     * @param   handle_t event_socket [IN]
     * @param   sockaddr_storage_t* sockaddr [IN]
     * @param   socket_context_t* socket_handle [IN]
     * @return  error code (see error.hpp)
     * @remarks copy socket and address
     */
    return_t connected(handle_t event_socket, sockaddr_storage_t* sockaddr, socket_context_t* socket_handle);
    /**
     * @brief   UDP
     */
    return_t udp_session_open(handle_t listen_sock);
    /**
     * @brief   dtls
     */
    return_t dtls_session_open(handle_t listen_sock);
    return_t dtls_session_open(handle_t listen_sock, const binary_t& cookie);
    /**
     * @brief   dtls
     */
    return_t dtls_session_handshake();
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
    netsocket_t* socket_info();
    netbuffer_t* get_buffer();

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
    http2_session* get_http2_session();

    return_t dgram_get_sockaddr(sockaddr_storage_t* addr);

   protected:
    return_t produce_stream(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr = nullptr);
    return_t produce_dgram(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr = nullptr);

   private:
    netsession_t _session;
    network_stream _stream;
    network_stream _request;
    network_session_data _session_data;

    http2_session* _http2_session;

    t_shared_reference<network_session> _shared;
    critical_section _lock;
};

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
     * @param   socket_context_t*      socket_handle      [IN]
     * @param   network_session**   ptr_session_object  [OUT] use release to free
     * @return  error code (see error.hpp)
     */
    return_t connected(handle_t event_socket, sockaddr_storage_t* sockaddr, server_socket* svr_socket, socket_context_t* socket_handle,
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
    return_t get_dgram_session(network_session** ptr_session_object, handle_t listen_sock, server_socket* svr_socket, socket_context_t* socket_handle);
    /**
     * @brief   [DTLS] handle dtls session
     */
    return_t get_dgram_cookie_session(network_session** ptr_session_object, handle_t listen_sock, const sockaddr_storage_t* sockaddr, server_socket* svr_socket,
                                      socket_context_t* socket_handle);
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
    // return_t dgram_find(const sockaddr_storage_t* sockaddr, network_session** ptr_session_object);

    return_t get_quic_session(network_session** ptr_session_object, handle_t listen_sock, server_socket* svr_socket, socket_context_t* socket_handle);

   protected:
    void shutdown();

   private:
    typedef std::map<handle_t, network_session*> network_session_map_t;
    typedef std::map<binary_t, network_session*> dgram_session_map_t;
    typedef std::map<binary_t, network_session*> quic_session_map_t;

    critical_section _session_lock;
    network_session_map_t _session_map;
    dgram_session_map_t _dgram_session_map;
    server_conf* _server_conf;
};

typedef struct netsocket_t net_session_socket_t;
typedef struct netsession_t net_session_t;
typedef network_session_data net_session_data;
typedef network_session net_session;
typedef network_session_manager net_session_manager;

}  // namespace net
}  // namespace hotplace

#endif
