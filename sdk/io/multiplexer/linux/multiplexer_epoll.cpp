/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/multiplexer/multiplexer.hpp>
#include <sys/epoll.h>
#include <unistd.h>

namespace hotplace {
namespace io {

#define MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE 0x20151030

typedef struct _MULTIPLEXER_EPOLL_CONTEXT : public multiplexer_context_t {
    uint32 signature;
    handle_t epoll_fd;
    int concurrent;
    struct epoll_event* events;
    multiplexer_controller_context_t* handle_event_loop;
} MULTIPLEXER_EPOLL_CONTEXT;

multiplexer_epoll::multiplexer_epoll ()
{
    // do nothing
}

multiplexer_epoll::~multiplexer_epoll ()
{
    // do nothing
}

return_t multiplexer_epoll::open (multiplexer_context_t** handle, size_t concurrent)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = nullptr;
    handle_t epollfd = -1;
    struct epoll_event* events = nullptr;
    multiplexer_controller_context_t* handle_event_loop = nullptr;
    multiplexer_controller controller;

    __try2
    {
        __try_new_catch (context, new MULTIPLEXER_EPOLL_CONTEXT, ret, __leave2);

        ret = controller.open (&handle_event_loop);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        events = (struct epoll_event*) malloc (sizeof (struct epoll_event) * concurrent);
        if (nullptr == events) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        epollfd = epoll_create (concurrent);
        if (epollfd < 0) {
            ret = errno;
            __leave2_trace (ret);
        }

        context->signature = MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE;
        context->epoll_fd = epollfd;
        context->events = events;
        context->concurrent = concurrent;
        context->handle_event_loop = handle_event_loop;

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != events) {
                free (events);
            }
            if (-1 != epollfd) {
                ::close (epollfd);
            }
            if (nullptr != context) {
                delete context;
            }
        }
    }

    return ret;
}

return_t multiplexer_epoll::close (multiplexer_context_t* handle)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = (MULTIPLEXER_EPOLL_CONTEXT *) handle;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        event_loop_break (handle);

        ::close (context->epoll_fd);
        free (context->events);

        controller.close (context->handle_event_loop);

        context->signature = 0;
        delete context;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::bind (multiplexer_context_t* handle, handle_t eventsource, void* data)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = (MULTIPLEXER_EPOLL_CONTEXT *) handle;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        struct epoll_event ev;
        memset (&ev, 0, sizeof (ev));
        ev.events = EPOLLIN | EPOLLHUP;
        ev.data.fd = eventsource;
        int ret_epoll_ctl = epoll_ctl (context->epoll_fd, EPOLL_CTL_ADD, eventsource, &ev);
        if (ret_epoll_ctl < 0) {
            ret = errno;
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::unbind (multiplexer_context_t* handle, handle_t eventsource, void* data)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = (MULTIPLEXER_EPOLL_CONTEXT *) handle;

    __try2
    {
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
        int ret_epoll_ctl = epoll_ctl (context->epoll_fd, EPOLL_CTL_DEL, eventsource, &ev);
        if (ret_epoll_ctl < 0) {
            ret = errno;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::event_loop_run (multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV event_callback_routine,
                                            void* parameter)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = (MULTIPLEXER_EPOLL_CONTEXT *) handle;
    arch_t token_handle = 0;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = controller.event_loop_new (context->handle_event_loop, &token_handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        //BOOL bRet = TRUE;
        while (true) {
            bool ret_event_loop_test_broken = controller.event_loop_test_broken (context->handle_event_loop, token_handle);
            if (true == ret_event_loop_test_broken) {
                break;
            }

            int ret_epoll_wait = epoll_wait (context->epoll_fd, context->events, context->concurrent, 100); // 100ms
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
                void* data_vector[4] = { nullptr, };
                data_vector[0] = handle;
                data_vector[1] = (void *) (arch_t) context->events[i].data.fd;

                if (context->events[i].data.fd == listenfd) {
                    event_callback_routine (mux_connect, 2, data_vector, &callback_control, parameter);
                } else if (context->events[i].events & EPOLLIN) {
                    event_callback_routine (mux_read, 2, data_vector, &callback_control, parameter);
                } else if ((context->events[i].events & EPOLLHUP) || (context->events[i].events & EPOLLERR)) {
                    event_callback_routine (mux_disconnect, 2, data_vector, &callback_control, parameter);
                }
            }
        }

        controller.event_loop_close (context->handle_event_loop, token_handle);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::event_loop_break (multiplexer_context_t* handle, arch_t* token_handle)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = (MULTIPLEXER_EPOLL_CONTEXT *) handle;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle || nullptr == token_handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */
        ret = controller.event_loop_break (context->handle_event_loop, token_handle);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::event_loop_break_concurrent (multiplexer_context_t* handle, size_t concurrent)
{
    return_t ret = errorcode_t::success;
    MULTIPLEXER_EPOLL_CONTEXT* context = (MULTIPLEXER_EPOLL_CONTEXT *) handle;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle || 0 == concurrent) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_EPOLL_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */
        ret = controller.event_loop_break_concurrent (context->handle_event_loop, concurrent);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_epoll::post (multiplexer_context_t* handle, uint32 size_vecotor, void* data_vector[])
{
    return_t ret = errorcode_t::success;

    return ret;
}

return_t multiplexer_epoll::setoption (multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue)
{
    return errorcode_t::not_supported;
}

multiplexer_type_t multiplexer_epoll::type ()
{
    return mux_type_epoll;
}

}
}  // namespace
