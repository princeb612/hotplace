/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKSESSION__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKSESSION__

#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/net/server/network_stream.hpp>

namespace hotplace {
using namespace io;
namespace net {

class network_priority_queue;
class server_socket;

/**
 * @brief session data
 */
class network_session_data : public key_value {
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
     * @param   handle_t            client_socket   [IN]
     * @param   sockaddr_storage_t* sockaddr        [IN]
     * @param   tls_context_t*      tls_handle      [IN]
     * @return  error code (see error.hpp)
     * @remarks copy socket and address
     */
    return_t connected(handle_t client_socket, sockaddr_storage_t* sockaddr, tls_context_t* tls_handle);
    /**
     * @brief in windows call wsarecv to read asynchronously
     * @return error code (see error.hpp)
     */
    return_t ready_to_read();

    /**
     * @brief send
     * @param const char*         data_ptr        [IN]
     * @param size_t              size_data       [IN]
     * @return error code (see error.hpp)
     */
    return_t send(const char* data_ptr, size_t size_data);

    /**
     * @brief return socket information
     */
    net_session_socket_t* socket_info();
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
     * @param   network_priority_queue* q               [IN]
     * @param   void*                   buf_read        [IN]
     * @param   size_t                  size_buf_read   [IN]
     * @remarks
     */
    return_t produce(network_priority_queue* q, void* buf_read, size_t size_buf_read);
    /**
     * @brief consume from stream and put into request, then read stream buffer list from request
     * @param   network_protocol_group* protocol_group              [IN]
     * @param   network_stream_data**   ptr_network_stream_buffer   [OUT] see network_stream::consume
     */
    return_t consume(network_protocol_group* protocol_group, network_stream_data** ptr_network_stream_buffer);

    server_socket* get_server_socket();
    network_session_data* get_session_data();

   protected:
    net_session_t _session;
    network_stream _stream;
    network_stream _request;
    network_session_data _session_data;

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

    /**
     * @brief   new network_session
     * @param   handle_t            client_socket       [IN]
     * @param   sockaddr_storage_t* sockaddr            [IN]
     * @param   server_socket*       svr_socket          [IN]
     * @param   tls_context_t*      tls_handle          [IN]
     * @param   network_session**    ptr_session_object  [OUT] use release to free
     * @return  error code (see error.hpp)
     */
    return_t connected(handle_t client_socket, sockaddr_storage_t* sockaddr, server_socket* svr_socket, tls_context_t* tls_handle,
                       network_session** ptr_session_object);
    /**
     * @brief   find a network session
     * @param   handle_t            client_socket       [IN]
     * @param   network_session**    ptr_session_object  [OUT] referenced, call release
     * @return  error code (see error.hpp)
     * @example
     *          network_session* session = session_manager.find (client_socket);
     *          if (nullptr != session)
     *          {
     *              session->release (); // decrease reference counter
     *          }
     */
    return_t find(handle_t client_socket, network_session** ptr_session_object);
    /**
     * @brief   operator[socket]
     * @return  error code (see error.hpp)
     * @remarks
     * @example
     *          network_session* session = session_manager[client_socket];
     *          if (nullptr != session)
     *          {
     *              session->release (); // decrease reference counter
     *          }
     */
    network_session* operator[](handle_t client_socket);
    /**
     * @brief   remove from session list
     * @param   handle_t          client_socket       [IN]
     * @param   network_session**  ptr_session_object  [OUT]
     * @return  error code (see error.hpp)
     */
    return_t ready_to_close(handle_t client_socket, network_session** ptr_session_object);

   protected:
    typedef std::map<handle_t, network_session*> network_session_map_t;
    typedef std::pair<network_session_map_t::iterator, bool> network_session_map_pib_t;

    critical_section _session_lock;
    network_session_map_t _session_map;
};

}  // namespace net
}  // namespace hotplace

#endif
