/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKSERVER__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKSERVER__

#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/basic/server_socket.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

enum netserver_callback_type_t {
    netserver_callback_type_socket = 0,
    netserver_callback_type_dataptr = 1,
    netserver_callback_type_datasize = 2,
    netserver_callback_type_session = 3,
};

typedef return_t (*ACCEPT_CONTROL_CALLBACK_ROUTINE)(socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter);

struct _network_multiplexer_context_t;
typedef struct _network_multiplexer_context_t network_multiplexer_context_t;

/**
 * @brief network_server
 * @remarks
 *  Server Prototype 1. NetServer (2010) supports windows only
 *  Server Prototype 2. network_server (2015) supports windows, linux
 *
 *  flow
 *  1. network i/o event (based on network_multiplexer - iocp, epoll, kqueue) - MultiplexerKqueue not implemented yet
 *  2. produce (network_thread in event_loop_run, put into raw stream)
 *  3. consume (consumer_thread in consumer_loop_run, put raw stream into composed stream, using protocol interpreter)
 *  4. call user_defined_callback (multiplexer_event_type_t::mux_read, vector data)
 *
 * @example
 *
 *  network_server netserver;
 *  network_multiplexer_context_t* handle = nullptr;
 *  netserver.open (&handle, AF_INET,  IPPROTO_TCP, PORT, 32000, NetworkRoutine, nullptr);
 *  netserver.consumer_loop_run (handle, 2);
 *  netserver.event_loop_run (handle, 2);
 *
 *  // ...
 *
 *  netserver.event_loop_break (handle, 2);
 *  netserver.consumer_loop_break (handle, 2);
 *  netserver.close (handle);
 *
 * @example
 *
 *  / callback
 *  uint16 NetworkRoutine (uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context)
 *  {
 *     uint32 ret = errorcode_t::success;
 *     net_session_socket_t* pSession = (net_session_socket_t*)data_array[netserver_callback_type_t::netserver_callback_type_socket]; // [0]
 *     char* buf = (char*)data_array[netserver_callback_type_t::netserver_callback_type_dataptr]; // [1]
 *     size_t bufsize = (size_t)data_array[netserver_callback_type_t::netserver_callback_type_datasize]; // [2]
 *
 *     switch(type)
 *     {
 *     case multiplexer_event_type_t::mux_connect:
 *         _log(LOGHELPER_DEBUG, "connect %d", pSession->client_socket);
 *         break;
 *     case multiplexer_event_type_t::mux_read:
 *         _log(LOGHELPER_DEBUG, "read %d msg [\n%.*s]", pSession->client_socket, bufsize, buf);
 *         break;
 *     case multiplexer_event_type_t::mux_disconnect:
 *         _log(LOGHELPER_DEBUG, "disconnect %d", pSession->client_socket);
 *         break;
 *     }
 *     return ret;
 *  }
 *
 */
class network_server {
   public:
    network_server();
    ~network_server();

    /**
     * @brief   open
     * @param   network_multiplexer_context_t** handle              [OUT] handle
     * @param   unsigned int                    family              [IN] AF_INET for ipv4, AF_INET6 for ipv6
     * @param   unsigned int                    type                [IN] ip protocol, IPPROTO_TCP(or IPPROTO_TCP)
     * @param   uint16                          port                [IN] port
     * @param   uint32                          concurrent          [IN] concurrent (linux epoll concerns, windows ignore)
     *                                                               see epoll_wait
     * @param   TYPE_CALLBACK_HANDLEREXV    callback_routine    [IN] callback
     *            return_t (*TYPE_CALLBACK_HANDLEREXV)
     *                         (uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter);
     *            parameter 1
     *              multiplexer_event_type_t::mux_connect
     *              multiplexer_event_type_t::mux_read
     *              multiplexer_event_type_t::mux_write
     *              multiplexer_event_type_t::mux_disconnect
     *            parameter 2
     *              RTL_NUMBER_OF(third parameter)
     *            parameter 3
     *              data_array[0] net_session_socket_t*
     *                equivalant data_array[netserver_callback_type_t::netserver_callback_type_socket]
     *              data_array[1] transfered buffer
     *                equivalant data_array[netserver_callback_type_t::netserver_callback_type_dataptr]
     *              data_array[2] transfered size
     *                equivalant data_array[netserver_callback_type_t::netserver_callback_type_datasize]
     *              data_array[3] network_session*
     *                equivalant data_array[netserver_callback_type_t::netserver_callback_type_session]
     *            parameter 4
     *              CALLBACK_CONTROL* is always null
     *            parameter 5
     *              see void* callback_param
     *
     *            parameter 1
     *              multiplexer_event_type_t::mux_tryconnect
     *            parameter 2
     *              RTL_NUMBER_OF(third parameter)
     *            parameter 3
     *              data_array[0] socket
     *              data_array[1] sockaddr_storage_t*
     *
     * @param   void*                           callback_param      [IN] callback parameter
     * @param   server_socket*                  svr_socket          [IN] socket layer (see also server_socket, transport_layer_security_server)
     * @return  error code (see error.hpp)
     * @remarks
     *          It'll be automatically created 1 tls_accept_thread, if server_socketis an instance of transport_layer_security_server class.
     *          see tls_accept_loop_run/tls_accept_loop_break
     */
    return_t open(network_multiplexer_context_t** handle, unsigned int family, unsigned int type, uint16 port, uint32 concurent,
                  TYPE_CALLBACK_HANDLEREXV lpfnEventHandler, void* lpParameter, server_socket* svr_socket);

    /**
     * @brief   access control or handle tcp before tls upgrade
     * @param   network_multiplexer_context_t* handle [in]
     * @param   ACCEPT_CONTROL_CALLBACK_ROUTINE accept_control_handler  [in]
     * @return  error code (see error.hpp)
     * @remarks
     *    typedef return_t (*ACCEPT_CONTROL_CALLBACK_ROUTINE)
     *       (socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter);
     *
     *  1. ip address control
     *
     *    ipaddr_acl acl;
     *    acl.add_rule ("127.0.0.1", true);
     *    acl.add_rule ("::1", true);
     *    acl.setmode (IPADDRESS_ACCESS_CONTROL_WHITELIST);
     *    bool result = false;
     *
     *    // accept only source address is 127.0.0.1 or ::1
     *    return_t accept_handler (socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter)
     *    {
     *      acl.determine (client_addr, result);
     *      if (control) *control = result ? CONTINUE_CONTROL : STOP_CONTROL;
     *      // ...
     *    }
     *
     *  2. if protocol upgrade needed, use accept_control_handler callback
     *    return_t accept_handler (socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter)
     *    {
     *      ::send (socket, message_data, message_length);
     *      // ...
     *    }
     */
    return_t set_accept_control_handler(network_multiplexer_context_t* handle, ACCEPT_CONTROL_CALLBACK_ROUTINE accept_control_handler);

    /**
     * @brief   add protocol interpreter
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   network_protocol* protocol [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          increase protocol reference counter
     */
    return_t add_protocol(network_multiplexer_context_t* handle, network_protocol* protocol);
    /**
     * @brief   remove protocol interpreter (by protocol_id)
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   network_protocol* protocol [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          decrease protocol reference counter
     */
    return_t remove_protocol(network_multiplexer_context_t* handle, network_protocol* protocol);
    /**
     * @brief   clear protocol
     * @param   network_multiplexer_context_t* handle  [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          implicitly close method call clear_protocols
     */
    return_t clear_protocols(network_multiplexer_context_t* handle);
    /**
     * @brief   create/stop tls_accept thread
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   uint32  concurrent_loop [IN] thread count
     * @return  error code (see error.hpp)
     */
    return_t tls_accept_loop_run(network_multiplexer_context_t* handle, uint32 concurrent_loop);
    return_t tls_accept_loop_break(network_multiplexer_context_t* handle, uint32 concurrent_loop);
    /**
     * @brief   create/stop event thread
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   uint32  concurrent_loop [IN] thread count
     * @return  error code (see error.hpp)
     * @remarks
     */
    return_t event_loop_run(network_multiplexer_context_t* handle, uint32 concurrent_loop);
    return_t event_loop_break(network_multiplexer_context_t* handle, uint32 concurrent_loop);
    /**
     * @brief   create/stop consumer thread
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   uint32  concurrent_loop [IN] thread count
     * @return  error code (see error.hpp)
     */
    return_t consumer_loop_run(network_multiplexer_context_t* handle, uint32 concurrent_loop);
    return_t consumer_loop_break(network_multiplexer_context_t* handle, uint32 concurrent_loop);

    /**
     * @brief   close
     * @param   network_multiplexer_context_t* handle [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *  do many following things
     *  1) signal and wait accept-related threads
     *  2) signal and wait protocol-related threads
     *  3) signal and wait service-related threads
     *  4) release all protocols (clear_protocols)
     *  5) close epoll multiplexer
     */
    return_t close(network_multiplexer_context_t* handle);

   protected:
    /**
     * @brief   tcp accept
     * @return  error code (see error.hpp)
     */
    static return_t accept_thread(void* user_context);
    return_t accept_routine(network_multiplexer_context_t* handle);
    /**
     * @brief accepted, before tlsaccept
     * @param network_multiplexer_context_t* handle [in]
     * @param socket_t client_socket [in]
     * @param sockaddr_storage_t* client_addr [in]
     */
    return_t try_connect(network_multiplexer_context_t* handle, socket_t client_socket, sockaddr_storage_t* client_addr);
    return_t tls_accept_ready(network_multiplexer_context_t* handle, bool* ready);
    /**
     * @brief   Tls accept
     * @return  error code (see error.hpp)
     */
    static return_t tls_accept_thread(void* user_context);
    return_t tls_accept_routine(network_multiplexer_context_t* handle);
    /**
     * @brief   stop 1 tls_accept_thread
     * @return  error code (see error.hpp)
     */
    static return_t tls_accept_signal(void* user_context);
    /**
     * @brief   stop tls_accept
     * @return  error code (see error.hpp)
     */
    return_t cleanup_tls_accept(network_multiplexer_context_t* handle);

    /**
     * @brief   read packet and compose a request
     * @return  error code (see error.hpp)
     */
    static return_t network_thread(void* user_context);
    /**
     * @brief   network processor
     * @param   uint32              type                [IN] see mux_event_type
     * @param   uint32              data_count          [IN] count
     * @param   void*               data_array[]        [IN] data
     * @param   CALLBACK_CONTROL*   callback_control    [IN] nullptr
     * @param   void*               user_context        [IN] see open method
     * @return  error code (see error.hpp)
     * @remarks
     *          see callback parameter of multiplexer_xxx::event_loop_run
     */
    static return_t network_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context);
    /**
     * @brief   stop 1 network_thread
     * @return  error code (see error.hpp)
     */
    static return_t network_signal(void* user_context);

    /**
     * @brief   if a request is composed, dispatch a request into callback
     * @return  error code (see error.hpp)
     */
    static return_t consumer_thread(void* user_context);

    return_t consumer_routine(network_multiplexer_context_t* handle);

    // signal ... see signal_wait_threads, signalwait_thread_routine

    /**
     * @brief   stop 1 consumer_thread
     * @return  error code (see error.hpp)
     */
    static return_t consumer_signal(void* user_context);

    /**
     * @brief   accept
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   tls_context_t* tls_handle      [IN]
     * @param   handle_t client_socket   [IN]
     * @param   sockaddr_storage_t* client_addr     [IN]
     * @return  error code (see error.hpp)
     * @remarks
     */
    return_t session_accepted(network_multiplexer_context_t* handle, tls_context_t* tls_handle, handle_t client_socket, sockaddr_storage_t* client_addr);
    /**
     * @brief   connection-close detected
     * @param   network_multiplexer_context_t* handle [IN]
     * @param   handle_t client_socket [IN]
     * @return  error code (see error.hpp)
     */
    return_t session_closed(network_multiplexer_context_t* handle, handle_t client_socket);
};

}  // namespace net
}  // namespace hotplace

#endif
