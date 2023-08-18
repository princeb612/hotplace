/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_MULTIPLEXER__
#define __HOTPLACE_SDK_IO_MULTIPLEXER__

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace io {

enum multiplexer_type_t {
    mux_type_completionport = 1,    /* Windows, Solaris 10, AIX 5 */
    mux_type_epoll          = 2,    /* linux */
    mux_type_kqueue         = 3,    /* Mac */
};

enum multiplexer_event_type_t {
    mux_tryconnect  = 0,    /* try to sslaccept */
    mux_connect     = 1,    /* connected */
    mux_read        = 2,    /* read */
    mux_write       = 3,    /* send */
    mux_disconnect  = 4,    /* closed */
};

typedef struct {} multiplexer_context_t;
typedef struct {} multiplexer_controller_context_t;

/*
 * @breif   windows iocp
 * @sample
 *
 *          // step.1 create a listen socket and handle
 *          server_socket = WSASocket (family, type, proto, nullptr, 0, WSA_FLAG_OVERLAPPED);
 *          mplexer.open (&handle, 0);
 *
 *          // step.2 create network thread and then
 *          mplexer.event_loop_run (handle, server_socket, NetworkRoutine, param);
 *
 *          // step.3 accept and bind
 *          client_socket = accept (server_socket, ...)
 *          mplexer.bind (handle, client_socket, param);
 *          WSARecv (client_socket, ...);
 *
 *          // step.4 network routine
 *          return_t NetworkRoutine (uint32 dwType, uint32 dwDataCount, void* pData[], CALLBACK_CONTROL* pControl, void* user_context)
 *          {
 *              uint32 BytesTransferred = (uint32)pData[1];
 *              LPNETSOCKET_CONTEXT* pData = (LPNETSOCKET_CONTEXT)pData[2];
 *              if (mux_read == dwType)
 *              {
 *                  ...
 *                  WSARecv (client_socket, ...);
 *              }
 *              if (mux_disconnect == dwType) ...
 *              // ...
 *          }
 *
 *          // step.5 stop accepting and break a network loop
 *          closesocket (server_socket);
 *          mplexer.event_loop_break_concurrent (handle, 1);
 *          mplexer.close (handle);
 *
 */
class multiplexer_iocp
{
public:
    multiplexer_iocp ();
    ~multiplexer_iocp ();

    /*
     * @brief open
     * @param   multiplexer_context_t** phandle [OUT] handle
     * @param   size_t reserved [IN] reserved
     * @return error code (see error.hpp)
     */
    return_t open (multiplexer_context_t** phandle, size_t reserved);
    /*
     * @brief close
     * @param   void* handle [IN] handle
     * @return error code (see error.hpp)
     */
    return_t close (multiplexer_context_t* handle);
    /*
     * @brief bind
     * @param   void* multiplexer_context_t [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* pData [IN] completion key, cannot be nullptr
     * @return error code (see error.hpp)
     */
    return_t bind (multiplexer_context_t* handle, handle_t eventsource, void* pData);
    /*
     * @brief unbind
     * @param   multiplexer_context_t* handle [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* pData [IN] completion key, cannot be nullptr
     * @return error code (see error.hpp)
     */
    return_t unbind (multiplexer_context_t* handle, handle_t eventsource, void* pData);
    /*
     * @brief loop
     * @param   multiplexer_context_t* handle [IN]
     * @param   handle_t listenfd [IN] reserved, ignore
     * @param   TYPE_CALLBACK_HANDLEREXV callback_routine [IN]
     * @param   void* user_context [IN]
     * @return error code (see error.hpp)
     * @reamrks
     *
     *   // see post method
     *   return_t NetworkRoutine (uint32 dwType, uint32 dwDataCount, void* pData[], CALLBACK_CONTROL* pControl, void* user_context)
     */
    return_t event_loop_run (multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV callback_routine, void* user_context);
    /*
     * @brief break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t* token_handle [INOPT] thread-id, if nullptr all event_loop_run stop
     * @return error code (see error.hpp)
     */
    return_t event_loop_break (multiplexer_context_t* handle, arch_t* token_handle = nullptr);
    /*
     * @brief break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   size_t concurrent [IN] call event_loop_break
     * @return error code (see error.hpp)
     */
    return_t event_loop_break_concurrent (multiplexer_context_t* handle, size_t concurrent);
    /*
     * @brief post
     * @param   multiplexer_context_t* handle [IN]
     * @param   uint32 dwDataCount [IN]
     * @pram    void* pData[] [IN]
     *                pData[0] ignore (multiplexer_iocp handle)
     *                pData[1] bytes transferred
     *                pData[2] completion key
     *                        see bind(void*, handle_t, void* pData)
     *                pData[3] overlapped (win32)
     * @return error code (see error.hpp)
     */
    return_t post (multiplexer_context_t* handle, uint32 dwDataCount, void* pData[]);
    /*
     * @brief setoption
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t optionvalue [IN]
     * @param   size_t size_optionvalue [IN]
     * @return error code (see error.hpp)
     * @remarks reserved
     */
    return_t setoption (multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue);
    /*
     * @brief   mux_type_completionport
     */
    multiplexer_type_t type ();

protected:
};

/*
 * @brief linux epoll
 * @sample
 *
 *    // step.1 create a listen socket and make a binding
 *    server_socket = socket (family, type, proto);
 *    mplexer.open (&handle, 32000);
 *    mplexer.bind (handle, server_socket, nullptr);
 *
 *    // step.2 create network thread and then
 *    mplexer.event_loop_run (handle, server_socket, NetworkRoutine, param);
 *
 *    // step.3 accept and bind
 *    // client_socket = accept
 *    mplexer.bind (handle, client_socket, param);
 *
 *    // step.4 network routine
 *    return_t NetworkRoutine (uint32 dwType, uint32 dwDataCount, void* pData[], CALLBACK_CONTROL* pControl, void* user_context)
 *    {
 *        uint32 BytesTransferred = (uint32)pData[1];
 *        LPNETSOCKET_CONTEXT* pData = (LPNETSOCKET_CONTEXT)pData[2];
 *        if (mux_connect == dwType) ...
 *        if (mux_read == dwType) ...
 *        // ...
 *    }
 *
 *    // step.5 stop accepting and break a network loop
 *    closesocket (server_socket);
 *    mplexer.event_loop_break_concurrent (handle, 1);
 *    mplexer.close (handle);
 *
 */
class multiplexer_epoll
{
public:
    multiplexer_epoll ();
    ~multiplexer_epoll ();

    /*
     * @brief open
     * @param   multiplexer_context_t** phandle [OUT]
     * @param   size_t concurrent [IN] epoll_create parameter
     * @return error code (see error.hpp)
     */
    return_t open (multiplexer_context_t** handle, size_t concurrent);
    /*
     * @brief close
     * @param   multiplexer_context_t* handle [IN]
     * @return error code (see error.hpp)
     */
    return_t close (multiplexer_context_t* handle);
    /*
     * @brief bind
     * @param   multiplexer_context_t* handle [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* pData [IN] can be nullptr
     * @return error code (see error.hpp)
     */
    return_t bind (multiplexer_context_t* handle, handle_t eventsource, void* pData);
    /*
     * @brief unbind
     * @param   multiplexer_context_t* handle [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* pData [IN] can be nullptr
     * @return error code (see error.hpp)
     */
    return_t unbind (multiplexer_context_t* handle, handle_t eventsource, void* pData);

    /*
     * @brief loop
     * @param   multiplexer_context_t* handle [IN]
     * @param   handle_t listenfd [IN]
     * @param   TYPE_CALLBACK_HANDLEREXV lpfnEventHandler [IN]
     *              pData[0] multiplexer_epoll handle
     *              pData[1] eventsource depends on multiplexer_event_type_t
     *              mux_connect listen-socket
     *              mux_read client-socket
     * @param   void* user_context [IN]
     * @return error code (see error.hpp)
     * @reamrks
     */
    return_t event_loop_run (multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV lpfnEventHandler, void* user_context);
    /*
     * @brief break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t* token_handle [INOPT] thread-id, if nullptr all event_loop_run stop
     * @return error code (see error.hpp)
     */
    return_t event_loop_break (multiplexer_context_t* handle, arch_t* token_handle = nullptr);
    /*
     * @brief break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   size_t concurrent [IN] call event_loop_break
     * @return error code (see error.hpp)
     */
    return_t event_loop_break_concurrent (multiplexer_context_t* handle, size_t concurrent);
    /*
     * @brief post
     * @param   multiplexer_context_t* handle [IN]
     * @param   uint32 dwDataCount [IN]
     * @pram    void* pData[] [IN]
     * @return error code (see error.hpp)
     * @remarks
     *          do nothing
     */
    return_t post (multiplexer_context_t* handle, uint32 dwDataCount, void* pData[]);
    /*
     * @brief setoption
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t optionvalue [IN]
     * @param   size_t size_optionvalue [IN]
     * @return error code (see error.hpp)
     * @remarks reserved
     */
    return_t setoption (multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue);
    /*
     * @brief mux_type_epoll
     */
    multiplexer_type_t type ();

protected:

};

/*
 * @brief support event_loop_break (multiplexer_iocp, multiplexer_epoll, MultiplexerKqueue)
 */
class multiplexer_controller
{
public:
    multiplexer_controller ();
    ~multiplexer_controller ();

    /*
     * @brief create a handle
     * @param   multiplexer_controller_context_t** handle [OUT] handle
     * @return error code (see error.hpp)
     */
    return_t open (multiplexer_controller_context_t** handle);
    /*
     * @brief destroy a handle
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @return error code (see error.hpp)
     */
    return_t close (multiplexer_controller_context_t* handle);

    /*
     * @brief allocate signal per thread-id
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t*   token_handle [OUT] token, as is thread-id
     * @return error code (see error.hpp)
     */
    return_t event_loop_new (multiplexer_controller_context_t* handle, arch_t* token_handle);
    /*
     * @brief send signal
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t* token_handle [IN] if nullptr, all event_loop_run stop
     * @return error code (see error.hpp)
     */
    return_t event_loop_break (multiplexer_controller_context_t* handle, arch_t* token_handle);
    /*
     * @brief send signal
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   size_t concurrent [IN] number of concurrent threads
     * @return error code (see error.hpp)
     */
    return_t event_loop_break_concurrent (multiplexer_controller_context_t* handle, size_t concurrent);
    /*
     * @brief wait signal
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t token_handle [IN] token
     */
    bool event_loop_test_broken (multiplexer_controller_context_t* handle, arch_t token_handle);
    /*
     * @brief free resource
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t token_handle [IN] token
     * @return error code (see error.hpp)
     */
    return_t event_loop_close (multiplexer_controller_context_t* handle, arch_t token_handle);
};


}
}  // namespace

#endif
