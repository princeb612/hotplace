/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_MULTIPLEXER__
#define __HOTPLACE_SDK_IO_SYSTEM_MULTIPLEXER__

#include <sdk/base/callback.hpp>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {
namespace io {

enum multiplexer_type_t {
    mux_type_completionport = 1, /* Windows, Solaris 10, AIX 5 */
    mux_type_epoll = 2,          /* linux */
    mux_type_kqueue = 3,         /* Mac, FreeBSD */
};

enum multiplexer_event_type_t {
    mux_tryconnect = 0, /* try to sslaccept */
    mux_connect = 1,    /* stream connected */
    mux_read = 2,       /* stream read */
    mux_write = 3,      /* stream send, reserved */
    mux_disconnect = 4, /* stream closed */
    mux_dgram = 5,      /* datagram read */
};

typedef struct {
} multiplexer_context_t;
typedef struct {
} multiplexer_controller_context_t;

/**
 * @breif   windows iocp
 * @example
 *
 *          // step.1 create a listen socket and handle
 *          svr_socket = WSASocket (family, type, proto, nullptr, 0, WSA_FLAG_OVERLAPPED);
 *          mplexer.open (&handle, 0);
 *
 *          // step.2 create network thread and then
 *          mplexer.event_loop_run (handle, svr_socket, NetworkRoutine, param);
 *
 *          // step.3 accept and bind
 *          cli_socket = accept (svr_socket, ...)
 *          mplexer.bind (handle, cli_socket, param);
 *          WSARecv (cli_socket, ...);
 *
 *          // step.4 network routine
 *          return_t NetworkRoutine (uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* user_context)
 *          {
 *              uint32 BytesTransferred = (uint32)data[1];
 *              LPNETSOCKET_CONTEXT* data = (LPNETSOCKET_CONTEXT)data[2];
 *              if (multiplexer_event_type_t::mux_read == type)
 *              {
 *                  ...
 *                  WSARecv (cli_socket, ...);
 *              }
 *              if (multiplexer_event_type_t::mux_disconnect == type) ...
 *              // ...
 *          }
 *
 *          // step.5 stop accepting and break a network loop
 *          closesocket (svr_socket);
 *          mplexer.event_loop_break_concurrent (handle, 1);
 *          mplexer.close (handle);
 *
 */
class multiplexer_iocp {
   public:
    multiplexer_iocp();
    ~multiplexer_iocp();

    /**
     * @brief   open
     * @param   multiplexer_context_t** phandle [OUT] handle
     * @param   size_t reserved [IN] reserved
     * @return  error code (see error.hpp)
     */
    return_t open(multiplexer_context_t** phandle, size_t reserved);
    /**
     * @brief   close
     * @param   void* handle [IN] handle
     * @return  error code (see error.hpp)
     */
    return_t close(multiplexer_context_t* handle);
    /**
     * @brief   bind
     * @param   void* multiplexer_context_t [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* data [IN] completion key, cannot be nullptr
     * @return  error code (see error.hpp)
     */
    return_t bind(multiplexer_context_t* handle, handle_t eventsource, void* data);
    /**
     * @brief   unbind
     * @param   multiplexer_context_t* handle [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* data [IN] completion key, cannot be nullptr
     * @return  error code (see error.hpp)
     */
    return_t unbind(multiplexer_context_t* handle, handle_t eventsource, void* data);
    /**
     * @brief   loop
     * @param   multiplexer_context_t* handle [IN]
     * @param   handle_t listenfd [IN] reserved, ignore
     * @param   TYPE_CALLBACK_HANDLEREXV callback_routine [IN]
     * @param   void* user_context [IN]
     * @return  error code (see error.hpp)
     * @reamrks
     *
     *   // see post method
     *   return_t NetworkRoutine (uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* user_context)
     */
    return_t event_loop_run(multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV callback_routine, void* user_context);
    /**
     * @brief   break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t* token_handle [INOPT] thread-id, if nullptr all event_loop_run stop
     * @return  error code (see error.hpp)
     */
    return_t event_loop_break(multiplexer_context_t* handle, arch_t* token_handle = nullptr);
    /**
     * @brief   break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   size_t concurrent [IN] call event_loop_break
     * @return  error code (see error.hpp)
     */
    return_t event_loop_break_concurrent(multiplexer_context_t* handle, size_t concurrent);
    /**
     * @brief post
     * @param   multiplexer_context_t* handle [IN]
     * @param   uint32 count [IN]
     * @pram    void* data[] [IN]
     *                data[0] ignore (multiplexer_iocp handle)
     *                data[1] bytes transferred
     *                data[2] completion key
     *                        see bind(void*, handle_t, void* data)
     *                data[3] overlapped (win32)
     * @return  error code (see error.hpp)
     */
    return_t post(multiplexer_context_t* handle, uint32 count, void* data[]);
    /**
     * @brief   setoption
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t optionvalue [IN]
     * @param   size_t size_optionvalue [IN]
     * @return  error code (see error.hpp)
     * @remarks reserved
     */
    return_t setoption(multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue);
    /**
     * @brief   mux_type_completionport
     */
    multiplexer_type_t type();

   protected:
};

/**
 * @brief linux epoll
 * @example
 *
 *    // step.1 create a listen socket and make a binding
 *    svr_socket = socket (family, type, proto);
 *    mplexer.open (&handle, 1024);
 *    mplexer.bind (handle, svr_socket, nullptr);
 *
 *    // step.2 create network thread and then
 *    mplexer.event_loop_run (handle, svr_socket, NetworkRoutine, param);
 *
 *    // step.3 accept and bind
 *    cli_socket = accept
 *    mplexer.bind (handle, cli_socket, param);
 *
 *    // step.4 network routine
 *    return_t NetworkRoutine (uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* user_context)
 *    {
 *        uint32 BytesTransferred = (uint32)data[1];
 *        LPNETSOCKET_CONTEXT* data = (LPNETSOCKET_CONTEXT)data[2];
 *        if (multiplexer_event_type_t::mux_connect == type) ...
 *        if (multiplexer_event_type_t::mux_read == type) ...
 *        // ...
 *    }
 *
 *    // step.5 stop accepting and break a network loop
 *    closesocket (svr_socket);
 *    mplexer.event_loop_break_concurrent (handle, 1);
 *    mplexer.close (handle);
 *
 */
class multiplexer_epoll {
   public:
    multiplexer_epoll();
    ~multiplexer_epoll();

    /**
     * @brief   open
     * @param   multiplexer_context_t** phandle [OUT]
     * @param   size_t concurrent [IN] epoll_create parameter
     * @return  error code (see error.hpp)
     */
    return_t open(multiplexer_context_t** handle, size_t concurrent);
    /**
     * @brief   close
     * @param   multiplexer_context_t* handle [IN]
     * @return  error code (see error.hpp)
     */
    return_t close(multiplexer_context_t* handle);
    /**
     * @brief   bind
     * @param   multiplexer_context_t* handle [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* data [IN] can be nullptr
     * @return  error code (see error.hpp)
     */
    return_t bind(multiplexer_context_t* handle, handle_t eventsource, void* data);
    /**
     * @brief   unbind
     * @param   multiplexer_context_t* handle [IN] handle
     * @param   handle_t eventsource [IN] client socket
     * @param   void* data [IN] can be nullptr
     * @return  error code (see error.hpp)
     */
    return_t unbind(multiplexer_context_t* handle, handle_t eventsource, void* data);

    /**
     * @brief loop
     * @param   multiplexer_context_t* handle [IN]
     * @param   handle_t listenfd [IN]
     * @param   TYPE_CALLBACK_HANDLEREXV lpfnEventHandler [IN]
     *              data[0] multiplexer_epoll handle
     *              data[1] eventsource depends on multiplexer_event_type_t
     *              multiplexer_event_type_t::mux_connect listen-socket
     *              multiplexer_event_type_t::mux_read client-socket
     * @param   void* user_context [IN]
     * @return  error code (see error.hpp)
     * @reamrks
     */
    return_t event_loop_run(multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV lpfnEventHandler, void* user_context);
    /**
     * @brief   break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t* token_handle [INOPT] thread-id, if nullptr all event_loop_run stop
     * @return  error code (see error.hpp)
     */
    return_t event_loop_break(multiplexer_context_t* handle, arch_t* token_handle = nullptr);
    /**
     * @brief   break event_loop_run method
     * @param   multiplexer_context_t* handle [IN]
     * @param   size_t concurrent [IN] call event_loop_break
     * @return  error code (see error.hpp)
     */
    return_t event_loop_break_concurrent(multiplexer_context_t* handle, size_t concurrent);
    /**
     * @brief   post
     * @param   multiplexer_context_t* handle [IN]
     * @param   uint32 count [IN]
     * @pram    void* data[] [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          do nothing
     */
    return_t post(multiplexer_context_t* handle, uint32 count, void* data[]);
    /**
     * @brief   setoption
     * @param   multiplexer_context_t* handle [IN]
     * @param   arch_t optionvalue [IN]
     * @param   size_t size_optionvalue [IN]
     * @return  error code (see error.hpp)
     * @remarks reserved
     */
    return_t setoption(multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue);
    /**
     * @brief mux_type_epoll
     */
    multiplexer_type_t type();

   protected:
};

/**
 * @brief support event_loop_break (multiplexer_iocp, multiplexer_epoll, MultiplexerKqueue)
 */
class multiplexer_controller {
   public:
    multiplexer_controller();
    ~multiplexer_controller();

    /**
     * @brief   create a handle
     * @param   multiplexer_controller_context_t** handle [OUT] handle
     * @return  error code (see error.hpp)
     */
    return_t open(multiplexer_controller_context_t** handle);
    /**
     * @brief   destroy a handle
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @return  error code (see error.hpp)
     */
    return_t close(multiplexer_controller_context_t* handle);

    /**
     * @brief   run (only one run per thread)
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t*   token_handle [OUT] token, thread id
     * @return  error code (see error.hpp)
     */
    return_t event_loop_new(multiplexer_controller_context_t* handle, arch_t* token_handle);
    /**
     * @brief   stop (one or all)
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t* token_handle [IN] if nullptr, all event_loop_run stop
     * @return  error code (see error.hpp)
     */
    return_t event_loop_break(multiplexer_controller_context_t* handle, arch_t* token_handle);
    /**
     * @brief   stop all
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   size_t concurrent [IN] number of concurrent threads
     * @return  error code (see error.hpp)
     */
    return_t event_loop_break_concurrent(multiplexer_controller_context_t* handle, size_t concurrent);
    /**
     * @brief   wait signal
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t token_handle [IN] token
     */
    bool event_loop_test_broken(multiplexer_controller_context_t* handle, arch_t token_handle);
    /**
     * @brief   free resource
     * @param   multiplexer_controller_context_t* handle [IN] handle
     * @param   arch_t token_handle [IN] token
     * @return  error code (see error.hpp)
     */
    return_t event_loop_close(multiplexer_controller_context_t* handle, arch_t token_handle);
};

}  // namespace io
}  // namespace hotplace

#endif
