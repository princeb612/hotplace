/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 *
 * references
 * https://man7.org/linux/man-pages/man2/epoll_create.2.html
 *  epoll_create    linux 2.6.8, glibc 2.3.2
 *  epoll_create1   linux 2.6.27, glibc 2.9
 */

#include <sys/epoll.h>
#include <unistd.h>

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/system/multiplexer.hpp>
#include <sdk/io/system/socket.hpp>

namespace hotplace {
namespace io {

#define MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE 0x20151030
// support Minum OS - Fedora Core 4
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0
#endif

typedef struct _multiplexer_epoll_context_t : public multiplexer_context_t {
    uint32 signature;
    handle_t epoll_fd;
    int concurrent;
    struct epoll_event* events;
    multiplexer_controller_context_t* handle_controller;
} multiplexer_epoll_context_t;

multiplexer_epoll::multiplexer_epoll() {
    // do nothing
}

multiplexer_epoll::~multiplexer_epoll() {
    // do nothing
}

return_t multiplexer_epoll::open(multiplexer_context_t** handle, size_t concurrent) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = nullptr;
    handle_t epollfd = -1;
    struct epoll_event* events = nullptr;
    multiplexer_controller_context_t* handle_controller = nullptr;
    multiplexer_controller controller;

    __try2 {
        __try_new_catch(context, new multiplexer_epoll_context_t, ret, __leave2);

        ret = controller.open(&handle_controller);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * concurrent);
        if (nullptr == events) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        epollfd = epoll_create(concurrent);
        if (epollfd < 0) {
            ret = errno;
            __leave2;
        }

        context->signature = MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE;
        context->epoll_fd = epollfd;
        context->events = events;
        context->concurrent = concurrent;
        context->handle_controller = handle_controller;

        *handle = context;

#if defined DEBUG
        if (istraceable(trace_category_internal)) {
            basic_stream dbs;
            dbs.println("epoll handle %i created", epollfd);
            trace_debug_event(trace_category_internal, trace_event_multiplexer, &dbs);
        }
#endif
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != events) {
                free(events);
            }
            if (-1 != epollfd) {
                ::close(epollfd);
            }
            if (nullptr != context) {
                delete context;
            }
        }
    }

    return ret;
}

return_t multiplexer_epoll::close(multiplexer_context_t* handle) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = (multiplexer_epoll_context_t*)handle;
    multiplexer_controller controller;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        event_loop_break(handle);

        ::close(context->epoll_fd);
        free(context->events);

        controller.close(context->handle_controller);

        context->signature = 0;
        delete context;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::bind(multiplexer_context_t* handle, handle_t eventsource, void* data) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = (multiplexer_epoll_context_t*)handle;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
        ev.data.fd = eventsource;
        int ret_epoll_ctl = epoll_ctl(context->epoll_fd, EPOLL_CTL_ADD, eventsource, &ev);
        if (ret_epoll_ctl < 0) {
            ret = errno;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_internal)) {
            basic_stream dbs;
            dbs.println("epoll handle %i bind %i", context->epoll_fd, eventsource);
            trace_debug_event(trace_category_internal, trace_event_multiplexer, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::unbind(multiplexer_context_t* handle, handle_t eventsource, void* data) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = (multiplexer_epoll_context_t*)handle;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = eventsource;
        int ret_epoll_ctl = epoll_ctl(context->epoll_fd, EPOLL_CTL_DEL, eventsource, &ev);
        if (ret_epoll_ctl < 0) {
            ret = errno;
            __leave2;
        }
#if defined DEBUG
        if (istraceable(trace_category_internal)) {
            basic_stream dbs;
            dbs.println("epoll handle %i unbind %i", context->epoll_fd, eventsource);
            trace_debug_event(trace_category_internal, trace_event_multiplexer, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::event_loop_run(multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV event_callback_routine, void* parameter) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = (multiplexer_epoll_context_t*)handle;
    arch_t token_handle = 0;
    multiplexer_controller controller;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = controller.event_loop_new(context->handle_controller, &token_handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        int socktype = 0;
        typeof_socket((socket_t)listenfd, socktype);
        bool is_dgram = (SOCK_DGRAM == socktype);

        int is_listen_socket = 0;
        if (SOCK_STREAM == socktype) {
            socklen_t optlen = sizeof(is_listen_socket);
            getsockopt(listenfd, SOL_SOCKET, SO_ACCEPTCONN, (char*)&is_listen_socket, &optlen);
        }

        while (true) {
            bool ret_event_loop_test_broken = controller.event_loop_test_broken(context->handle_controller, token_handle);
            if (true == ret_event_loop_test_broken) {
                break;
            }

            int ret_epoll_wait = epoll_wait(context->epoll_fd, context->events, context->concurrent, 100);  // 100ms
            if (0 == ret_epoll_wait) {
                continue;
            }
            if (ret_epoll_wait < 0) {
                if (EINTR == errno) {
                    continue;
                } else {
                    break;
                }
            }

            for (int i = 0; i < ret_epoll_wait; i++) {
                CALLBACK_CONTROL callback_control = CONTINUE_CONTROL;
                void* data_vector[4] = {nullptr};
                data_vector[0] = handle;
                data_vector[1] = (void*)(arch_t)context->events[i].data.fd;

                if (context->events[i].events & EPOLLIN) {
                    multiplexer_event_type_t type = multiplexer_event_type_t::mux_read;
                    if (context->events[i].data.fd == listenfd) {
                        if (is_listen_socket) {
                            type = multiplexer_event_type_t::mux_connect;
                        } else if (is_dgram) {
                            type = multiplexer_event_type_t::mux_dgram;
                        }
                    }
                    event_callback_routine(type, 2, data_vector, &callback_control, parameter);
                } else if (context->events[i].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
                    event_callback_routine(multiplexer_event_type_t::mux_disconnect, 2, data_vector, &callback_control, parameter);
                }
            }
        }

        controller.event_loop_close(context->handle_controller, token_handle);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::event_loop_break(multiplexer_context_t* handle, arch_t* token_handle) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = (multiplexer_epoll_context_t*)handle;
    multiplexer_controller controller;

    __try2 {
        if (nullptr == handle || nullptr == token_handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */
        ret = controller.event_loop_break(context->handle_controller, token_handle);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::event_loop_break_concurrent(multiplexer_context_t* handle, size_t concurrent) {
    return_t ret = errorcode_t::success;
    multiplexer_epoll_context_t* context = (multiplexer_epoll_context_t*)handle;
    multiplexer_controller controller;

    __try2 {
        if (nullptr == handle || 0 == concurrent) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */
        ret = controller.event_loop_break_concurrent(context->handle_controller, concurrent);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::post(multiplexer_context_t* handle, uint32 size_vecotor, void* data_vector[]) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t multiplexer_epoll::setoption(multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue) { return errorcode_t::not_supported; }

multiplexer_type_t multiplexer_epoll::type() { return mux_type_epoll; }

}  // namespace io
}  // namespace hotplace
