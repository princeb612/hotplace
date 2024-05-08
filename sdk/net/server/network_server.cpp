/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <queue>
#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <sdk/net/server/network_server.hpp>

namespace hotplace {
using namespace io;
namespace net {

server_conf::server_conf() {}

server_conf::server_conf(const server_conf& conf) { _config_map = conf._config_map; }

server_conf& server_conf::set(netserver_config_t type, uint16 value) {
    return_t ret = errorcode_t::success;

    config_map_pib_t pib = _config_map.insert(std::make_pair(type, value));
    if (false == pib.second) {
        pib.first->second = value;
    }

    return *this;
}

uint16 server_conf::get(netserver_config_t type) {
    uint16 value = 0;

    config_map_t::iterator iter = _config_map.find(type);
    if (_config_map.end() != iter) {
        value = iter->second;
    }

    return value;
}

#define NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE 0x20151127

struct _network_multiplexer_context_t;
typedef struct _accept_context_t {
    struct _network_multiplexer_context_t* mplexer_context;
    socket_t cli_socket;
    sockaddr_storage_t client_addr;
    socklen_t client_addr_len;

    _accept_context_t() : mplexer_context(nullptr), cli_socket(INVALID_SOCKET) { client_addr_len = sizeof(client_addr); }

} accept_context_t;

typedef std::queue<accept_context_t> accept_queue_t;

typedef struct _network_multiplexer_context_t {
    uint32 signature;

    multiplexer_context_t* mplexer_handle;
    uint32 concurrent;
    TYPE_CALLBACK_HANDLEREXV callback_routine;
    void* callback_param;

    socket_t listen_sock;
    tcp_server_socket* svr_socket;

    semaphore tls_accept_mutex;
    semaphore cleanup_mutex;
    semaphore consumer_mutex;
    signalwait_threads network_threads;
#if defined _WIN32 || defined _WIN64
    signalwait_threads accept_threads;
#endif
    signalwait_threads tls_accept_threads;
    signalwait_threads consumer_threads;

    network_session_manager session_manager;
    t_mlfq<network_session> event_queue;

    network_protocol_group protocol_group;

    accept_queue_t accept_queue;
    critical_section accept_queue_lock;

    ACCEPT_CONTROL_CALLBACK_ROUTINE accept_control_handler;
} network_multiplexer_context_t;

network_server::network_server() {
    // openssl_startup ();
    // openssl_thread_setup ();

    // default values
    get_server_conf()
        .set(netserver_config_t::serverconf_concurrent_event, 1024)
        .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
        .set(netserver_config_t::serverconf_concurrent_network, 1)
        .set(netserver_config_t::serverconf_concurrent_consume, 2);
}

network_server::~network_server() {
    // openssl_thread_cleanup ();
    // openssl_cleanup ();
}

return_t network_server::open(network_multiplexer_context_t** handle, unsigned int family, unsigned int type, uint16 port, uint32 concurrent,
                              TYPE_CALLBACK_HANDLEREXV callback_routine, void* callback_param, tcp_server_socket* svr_socket) {
    return_t ret = errorcode_t::success;

    network_multiplexer_context_t* context = nullptr;
    socket_t sock = INVALID_SOCKET;
    multiplexer_context_t* mplexer_handle = nullptr;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle || nullptr == callback_routine || nullptr == svr_socket) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = svr_socket->listen(&sock, family, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = mplexer.open(&mplexer_handle, concurrent);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        __try_new_catch(context, new network_multiplexer_context_t, ret, __leave2);

#if defined __linux__

        // (epoll) bind server socket
        mplexer.bind(mplexer_handle, sock, nullptr);
        // (epoll) and then (see multiplexer_epoll::event_loop_run)
        //         if (fd == listen_socket) {
        //           event_callback_routine(multiplexer_event_type_t::mux_connect(...);
        //         }

#endif

#if defined _WIN32 || defined _WIN64
        // use dummy signal handler ... just call CloseListener first, and signal_and_wait_all
        context->accept_threads.set(1, accept_thread, signalwait_threads::dummy_signal, context);
#endif
        size_t concurrent_tls_accept = get_server_conf().get(netserver_config_t::serverconf_concurrent_tls_accept);
        size_t concurrent_network = get_server_conf().get(netserver_config_t::serverconf_concurrent_network);
        size_t concurrent_consume = get_server_conf().get(netserver_config_t::serverconf_concurrent_consume);

        context->tls_accept_threads.set(concurrent_tls_accept, tls_accept_thread, tls_accept_signal, context);
        context->network_threads.set(concurrent_network, network_thread, network_signal, context);
        context->consumer_threads.set(concurrent_consume, consumer_thread, consumer_signal, context);

        context->mplexer_handle = mplexer_handle;
        context->concurrent = concurrent;
        context->callback_routine = callback_routine;
        context->callback_param = callback_param;

        context->listen_sock = sock;
        context->svr_socket = svr_socket;

        context->accept_control_handler = nullptr;

        context->signature = NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE;

#if defined _WIN32 || defined _WIN64
        context->accept_threads.create();
        // (iocp) and then bind client socket after accept
#endif
        if (svr_socket->support_tls()) {
            context->tls_accept_threads.create();
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != mplexer_handle) {
                mplexer.close(mplexer_handle);
            }
            if (INVALID_SOCKET != sock) {
                if (svr_socket) {
                    svr_socket->close(sock, nullptr);
                }
            }
            if (nullptr != context) {
                delete context;
            }
        }
    }

    return ret;
}

return_t network_server::set_accept_control_handler(network_multiplexer_context_t* handle, ACCEPT_CONTROL_CALLBACK_ROUTINE accept_control_handler) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        handle->accept_control_handler = accept_control_handler;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::add_protocol(network_multiplexer_context_t* handle, network_protocol* protocol_ptr) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = handle->protocol_group.add(protocol_ptr);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::remove_protocol(network_multiplexer_context_t* handle, network_protocol* protocol_ptr) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = handle->protocol_group.remove(protocol_ptr);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::clear_protocols(network_multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = handle->protocol_group.clear();
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::tls_accept_loop_run(network_multiplexer_context_t* handle, uint32 concurrent_loop) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        tcp_server_socket* svr_socket = handle->svr_socket;
        if (svr_socket->support_tls()) {
            for (uint32 i = 0; i < concurrent_loop; i++) {
                handle->tls_accept_threads.create();
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::tls_accept_loop_break(network_multiplexer_context_t* handle, uint32 concurrent_loop) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        for (uint32 i = 0; i < concurrent_loop; i++) {
            handle->tls_accept_threads.signal();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::event_loop_run(network_multiplexer_context_t* handle, uint32 concurrent_loop) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* if a thread count of network_threads reachs max-concurrent, no more thread is created. */
        for (uint32 i = 0; i < concurrent_loop; i++) {
            handle->network_threads.create();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::event_loop_break(network_multiplexer_context_t* handle, uint32 concurrent_loop) {
    return_t ret = errorcode_t::success;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* stop threads */
        uint32 i = 0;
        for (i = 0; i < concurrent_loop; i++) {
            handle->network_threads.signal();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::consumer_loop_run(network_multiplexer_context_t* handle, uint32 concurrent_loop) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* if a thread count of consumer_threads reachs max-concurrent, no more thread is created. */
        for (uint32 i = 0; i < concurrent_loop; i++) {
            handle->consumer_threads.create();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::consumer_loop_break(network_multiplexer_context_t* handle, uint32 concurrent_loop) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* stop threads */
        for (uint32 i = 0; i < concurrent_loop; i++) {
            handle->consumer_threads.signal();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::close(network_multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        tcp_server_socket* svr_socket = handle->svr_socket;
        svr_socket->close(handle->listen_sock, nullptr);

        /* stop all threads */
#if defined _WIN32 || defined _WIN64
        handle->accept_threads.signal_and_wait_all();
#endif
        cleanup_tls_accept(handle);
        handle->tls_accept_threads.signal_and_wait_all();
        handle->network_threads.signal_and_wait_all();
        handle->consumer_threads.signal_and_wait_all();

        handle->protocol_group.clear();

        mplexer.close(handle->mplexer_handle);

        handle->signature = 0;
        delete handle;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::accept_thread(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        network_server svr;
        do {
            ret = svr.accept_routine(handle);
        } while (errorcode_t::success == ret);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::accept_routine(network_multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;
    network_server svr;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socket_t listen_sock = (socket_t)handle->listen_sock;
        tcp_server_socket* svr_socket = handle->svr_socket;

        accept_context_t accpt_ctx;
        accpt_ctx.mplexer_context = handle;

        ret = svr_socket->accept(listen_sock, &accpt_ctx.cli_socket, (struct sockaddr*)&accpt_ctx.client_addr, &accpt_ctx.client_addr_len);
        if (INVALID_SOCKET == accpt_ctx.cli_socket) {
            /* mingw environments GetLastError () return 0 */
#if defined __MINGW32__
            ret = errorcode_t::canceled;
#elif defined __linux__
            ret = get_errno(ret);
#elif defined _WIN32 || defined _WIN64
            ret = GetLastError();
#endif

            __leave2;
        }

        /* allow/deny based on a network address */
        /* if protocol upgrade needed, use accept_control_handler callback */
        if (nullptr != handle->accept_control_handler) {
            CALLBACK_CONTROL control = CONTINUE_CONTROL;
            handle->accept_control_handler(accpt_ctx.cli_socket, &accpt_ctx.client_addr, &control, handle->callback_param);
            if (STOP_CONTROL == control) {
                close_socket(accpt_ctx.cli_socket, true, 0);
                __leave2;
            }
        }

        /*
         * it can be accomplished by using follows...
         *
         * svr_socket->tls_accept(cli_socket, &tls_handle);
         * ret = svr.session_accepted(handle, tls_handle, (handle_t)cli_socket, &client_addr);
         *
         * sometimes it takes long time by calling ssl_accept
         * so, separate thread to improve accept performance
         */

        if (svr_socket->support_tls()) {
            /* prepare for ssl_accept delay */
            {
                critical_section_guard guard(handle->accept_queue_lock);
                handle->accept_queue.push(accpt_ctx);
            }

            svr.try_connect(handle, accpt_ctx.cli_socket, &accpt_ctx.client_addr);
        } else {
            ret = svr.session_accepted(handle, nullptr, (handle_t)accpt_ctx.cli_socket, &accpt_ctx.client_addr);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::try_connect(network_multiplexer_context_t* handle, socket_t cli_socket, sockaddr_storage_t* client_addr) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        void* dispatch_data[4] = {
            nullptr,
        };
        dispatch_data[0] = (void*)(arch_t)cli_socket;
        dispatch_data[1] = client_addr;
        handle->callback_routine(multiplexer_event_type_t::mux_tryconnect, 4, dispatch_data, nullptr, handle->callback_param);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_server::tls_accept_ready(network_multiplexer_context_t* handle, bool* ready) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == ready) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        bool ret_value = false;
        ret_value = handle->accept_queue.empty() ? false : true;
        *ready = ret_value;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_server::tls_accept_thread(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        network_server svr;
        uint32 ret_wait = 0;
        uint32 interval = 1;
        bool ready = false;

        while (true) {
            ready = false;
            svr.tls_accept_ready(handle, &ready);

            interval = (true == ready) ? 1 : 100; /* control cpu usage */
            ret_wait = handle->tls_accept_mutex.wait(interval);
            if (0 == ret_wait) {
                break;
            }

            if (true == ready) {
                svr.tls_accept_routine(handle);
            }
        }

        // openssl_thread_end (); // ssl23_accept memory leak, call for each thread
        handle->svr_socket->tls_stop_accept();
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::tls_accept_routine(network_multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        accept_context_t accpt_ctx;
        {
            critical_section_guard guard(handle->accept_queue_lock);
            if (false == handle->accept_queue.empty()) {
                accpt_ctx = handle->accept_queue.front();
                handle->accept_queue.pop();
            } else {
                ret = errorcode_t::empty;
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        network_server svr;
        tcp_server_socket* svr_socket = handle->svr_socket;
        tls_context_t* tls_handle = nullptr;

        return_t dwResult = svr_socket->tls_accept(accpt_ctx.cli_socket, &tls_handle);
        if (errorcode_t::success == dwResult) {
            svr.session_accepted(handle, tls_handle, (handle_t)accpt_ctx.cli_socket, &accpt_ctx.client_addr);
            /* tls_handle is release in session_closed member. */
        } else {
            close_socket(accpt_ctx.cli_socket, true, 0);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::tls_accept_signal(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->tls_accept_mutex.signal();
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::cleanup_tls_accept(network_multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        accept_context_t accpt_ctx;
        critical_section_guard guard(handle->accept_queue_lock);
        if (false == handle->accept_queue.empty()) {
            accpt_ctx = handle->accept_queue.front();
            handle->accept_queue.pop();
            close_socket(accpt_ctx.cli_socket, true, 0);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_server::network_thread(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = mplexer.event_loop_run(handle->mplexer_handle, (handle_t)handle->listen_sock, network_routine, handle);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::network_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* context = static_cast<network_multiplexer_context_t*>(user_context);
    network_server svr;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    // tcp_server_socket* serversocket = context->svr_socket;

#if defined _WIN32 || defined _WIN64

    uint32 transferred = (uint32)(arch_t)data_array[1];
    network_session* session_object = (network_session*)data_array[2];

    __try2 {
        if (multiplexer_event_type_t::mux_read == type) {
            /* consumer_routine (decrease), close_if_not_referenced (delete) */
            session_object->produce(&context->event_queue, (byte_t*)session_object->wsabuf_read()->buf, transferred);
            /* asynchronous write */
            session_object->ready_to_read();
        }
        if (multiplexer_event_type_t::mux_disconnect == type) {
            svr.session_closed(context, session_object->socket_info()->cli_socket);
        }
    }
    __finally2 {
        // do nothing
    }

#elif defined __linux__

    // void* handle = data_array[0];

    if (multiplexer_event_type_t::mux_connect == type) {
        svr.accept_routine(context);
    } else if (multiplexer_event_type_t::mux_read == type) {
        int sockcli = (int)(long)data_array[1];

        network_session* session_object = nullptr;
        ret = context->session_manager.find(sockcli, &session_object); /* reference increased, call release later */
        if (errorcode_t::success == ret) {
            /* consumer_routine (decrease), close_if_not_referenced (delete) */
            ret = session_object->produce(&context->event_queue, nullptr, 0);

            session_object->release(); /* find, refcount-- */

            if (errorcode_t::success == ret) {
                // do nothing
            } else {
                svr.session_closed(context, sockcli); /* call session_object->release() inside of closed */
            }
        }
    }
    // else if (multiplexer_event_type_t::mux_disconnect == type) /* no event catchable */

#endif

    return ret;
}

return_t network_server::network_signal(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        mplexer.event_loop_break_concurrent(handle->mplexer_handle, 1); /* call event_loop_break just 1 time */
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::consumer_thread(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        network_server svr;
        uint32 ret_wait = 0;

        while (true) {
            ret_wait = handle->consumer_mutex.wait(100);
            if (0 == ret_wait) {
                break;
            }

            svr.consumer_routine(handle);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::consumer_routine(network_multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;

    if (handle->event_queue.size()) {
        int priority = 0;
        network_session* session_object = nullptr;
        ret = handle->event_queue.pop(&priority, &session_object, 1);  // session priority
        if (errorcode_t::success == ret) {
            // re-order by stream priority
            network_stream_data* buffer_object = nullptr;
            session_object->consume(&handle->protocol_group, &buffer_object);  // set stream priority while processing network_protocol::read_stream

#if 0
            t_mlfq<network_stream_data> pri_queue;
            while (buffer_object) {
                pri_queue.post(buffer_object->get_priority(), buffer_object);
            
                network_stream_data* temp = buffer_object;
                buffer_object = buffer_object->next();
                temp->release();
            }

            // process by stream priority
            while (true) {
                return_t test = pri_queue.pop(&priority, &buffer_object, 1);
                if (errorcode_t::success != test) {
                    break;
                }
            
                void* dispatch_data[4] = {
                    nullptr,
                };
                dispatch_data[0] = session_object->socket_info(); /* netserver_cb_type_t::netserver_cb_socket */
                dispatch_data[1] = buffer_object->content();      /* netserver_cb_type_t::netserver_cb_dataptr */
                dispatch_data[2] = (void*)buffer_object->size();  /* netserver_cb_type_t::netserver_cb_datasize */
                dispatch_data[3] = session_object;                /* netserver_cb_type_t::netserver_cb_session */
            
                handle->callback_routine(multiplexer_event_type_t::mux_read, 4, dispatch_data, nullptr, handle->callback_param);
            
                buffer_object->release();
            }
#else
            while (buffer_object) {
                void* dispatch_data[4] = {
                    nullptr,
                };
                dispatch_data[0] = session_object->socket_info(); /* netserver_cb_type_t::netserver_cb_socket */
                dispatch_data[1] = buffer_object->content();      /* netserver_cb_type_t::netserver_cb_dataptr */
                dispatch_data[2] = (void*)buffer_object->size();  /* netserver_cb_type_t::netserver_cb_datasize */
                dispatch_data[3] = session_object;                /* netserver_cb_type_t::netserver_cb_session */

                handle->callback_routine(multiplexer_event_type_t::mux_read, 4, dispatch_data, nullptr, handle->callback_param);

                network_stream_data* temp = buffer_object;
                buffer_object = buffer_object->next();
                temp->release();
            }
#endif

            session_object->release();
        }
    } else {
        msleep(10);
    }

    return ret;
}

return_t network_server::consumer_signal(void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = reinterpret_cast<network_multiplexer_context_t*>(user_context);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        handle->consumer_mutex.signal();
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::session_accepted(network_multiplexer_context_t* handle, tls_context_t* tls_handle, handle_t cli_socket,
                                          sockaddr_storage_t* client_addr) {
    return_t ret = errorcode_t::success;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if ((nullptr == handle) || (INVALID_SOCKET == (socket_t)cli_socket) || (nullptr == client_addr)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        network_session* session_object;
        ret = handle->session_manager.connected(cli_socket, client_addr, handle->svr_socket, tls_handle, &session_object);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        /* associate with multiplex object (iocp, epoll) */
        mplexer.bind(handle->mplexer_handle, cli_socket, session_object);
#if defined _WIN32 || defined _WIN64
        /* asynchronous */
        session_object->ready_to_read();
#endif

        void* dispatch_data[4] = {
            nullptr,
        };
        dispatch_data[0] = (void*)session_object->socket_info(); /* NET_OBJECT_SOCKET* */
        handle->callback_routine(multiplexer_event_type_t::mux_connect, 4, dispatch_data, nullptr, handle->callback_param);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_server::session_closed(network_multiplexer_context_t* handle, handle_t cli_socket) {
    return_t ret = errorcode_t::success;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined __APPLE__
    multiplexer_kqueue mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    __try2 {
        if (nullptr == handle || INVALID_SOCKET == (socket_t)cli_socket) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (NETWORK_MULTIPLEXER_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        network_session* session_object = nullptr;
        /* remove from session manager, prevent double free(concurrent epoll_wait) */
        ret = handle->session_manager.ready_to_close(cli_socket, &session_object);
        if (errorcode_t::success == ret) {
            /* no more associated, control_delete */
            mplexer.unbind(handle->mplexer_handle, session_object->socket_info()->cli_socket, nullptr);

            void* dispatch_data[4] = {
                nullptr,
            };
            dispatch_data[0] = (void*)session_object->socket_info(); /* NET_OBJECT_SOCKET* */
            handle->callback_routine(multiplexer_event_type_t::mux_disconnect, 4, dispatch_data, nullptr, handle->callback_param);

            /* end-of-life. if reference counter is 0, close a socket and delete an instance */
            /* and release tls_handle here */
            session_object->release();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

server_conf& network_server::get_server_conf() { return _config; }

}  // namespace net
}  // namespace hotplace
