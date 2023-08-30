/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/system/multiplexer.hpp>

namespace hotplace {
namespace io {

#define MULTIPLEXER_IOCP_CONTEXT_SIGNATURE 0x20151030

typedef struct _multiplexer_iocp_context_t : public multiplexer_context_t {
    uint32 signature;
    HANDLE hIocp;
    multiplexer_controller_context_t* handle_controller;
} multiplexer_iocp_context_t;

multiplexer_iocp::multiplexer_iocp ()
{
    // do nothing
}

multiplexer_iocp::~multiplexer_iocp ()
{
    // do nothing
}

return_t multiplexer_iocp::open (multiplexer_context_t** handle, size_t concurrent)
{
    return_t ret = errorcode_t::success;
    multiplexer_iocp_context_t* pContext = nullptr;
    HANDLE hIocp = nullptr;
    multiplexer_controller_context_t* handle_controller = nullptr;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (pContext, new multiplexer_iocp_context_t, ret, __leave2);

        ret = controller.open (&handle_controller);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        hIocp = CreateIoCompletionPort (INVALID_HANDLE_VALUE, nullptr, 0, 0);

        pContext->signature = MULTIPLEXER_IOCP_CONTEXT_SIGNATURE;
        pContext->hIocp = hIocp;
        pContext->handle_controller = handle_controller;

        *handle = pContext;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_iocp::close (multiplexer_context_t* handle)
{
    return_t ret = errorcode_t::success;
    multiplexer_iocp_context_t* pContext = (multiplexer_iocp_context_t*) handle;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_IOCP_CONTEXT_SIGNATURE != pContext->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        event_loop_break (handle);

        CloseHandle (pContext->hIocp);

        controller.close (pContext->handle_controller);

        pContext->signature = 0;
        delete pContext;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t multiplexer_iocp::bind (multiplexer_context_t* handle, handle_t eventsource, void* data)
{
    return_t ret = errorcode_t::success;
    multiplexer_iocp_context_t* pContext = (multiplexer_iocp_context_t*) handle;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_IOCP_CONTEXT_SIGNATURE != pContext->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        HANDLE handle = CreateIoCompletionPort (eventsource, pContext->hIocp, (ULONG_PTR) data, 0);
        if (nullptr == handle) {
            ret = GetLastError ();
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t multiplexer_iocp::unbind (multiplexer_context_t* handle, handle_t eventsource, void* data)
{
    return_t ret = errorcode_t::success;

    return ret;
}

return_t multiplexer_iocp::event_loop_run (multiplexer_context_t* handle, handle_t listenfd, TYPE_CALLBACK_HANDLEREXV event_callback_routine,
                                           void* parameter)
{
    return_t ret = errorcode_t::success;
    multiplexer_iocp_context_t* pContext = (multiplexer_iocp_context_t*) handle;
    UINT_PTR token_handle = 0;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_IOCP_CONTEXT_SIGNATURE != pContext->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = controller.event_loop_new (pContext->handle_controller, &token_handle);

        BOOL bRet = TRUE;
        while (true) {
            bool broken = controller.event_loop_test_broken (pContext->handle_controller, token_handle);
            if (true == broken) {
                break;
            }

            // GetQueuedCompletionStatus
            // GetQueuedCompletionStatusEx : retrieves multiple completion port entries simultaneously
            DWORD size_transfered = 0;
            ULONG_PTR completion_key = 0;
            LPOVERLAPPED overlapped = nullptr;
            bRet = GetQueuedCompletionStatus (pContext->hIocp, &size_transfered, &completion_key, &overlapped, 100);
            if ((FALSE == bRet) && (nullptr == overlapped)) {
                ret = GetLastError ();
                if (WAIT_TIMEOUT == ret) {                  /* timeout */
                    continue;
                } else if (errorcode_t::success == ret) {   /* mingw environments */
                    continue;
                } else {
                    break; // GLE - Windows 2003 returns 87, Windows 7 returns 735
                }
            }
            if (0 == completion_key) {
                // response event_loop_break
                break;
            }
            void* data_vector[4] = { nullptr, };
            data_vector[0] = (void*) handle;
            data_vector[1] = (void*) (arch_t) size_transfered;
            data_vector[2] = (void*) completion_key;
            data_vector[3] = (void*) overlapped;

            DWORD type = 0;
            if (0 == size_transfered) {
                type = multiplexer_event_type_t::mux_disconnect;
            } else {
                type = multiplexer_event_type_t::mux_read;
            }

            event_callback_routine (type, 4, data_vector, nullptr, parameter);
        }

        controller.event_loop_close (pContext->handle_controller, token_handle);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t multiplexer_iocp::event_loop_break (multiplexer_context_t* handle, arch_t* token_handle)
{
    return_t ret = errorcode_t::success;
    multiplexer_iocp_context_t* pContext = (multiplexer_iocp_context_t*) handle;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_IOCP_CONTEXT_SIGNATURE != pContext->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */
        ret = controller.event_loop_break (pContext->handle_controller, token_handle);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t multiplexer_iocp::event_loop_break_concurrent (multiplexer_context_t* handle, size_t concurrent)
{
    return_t ret = errorcode_t::success;
    multiplexer_iocp_context_t* pContext = (multiplexer_iocp_context_t*) handle;
    multiplexer_controller controller;

    __try2
    {
        if (nullptr == handle || 0 == concurrent) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_IOCP_CONTEXT_SIGNATURE != pContext->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* signal */
        ret = controller.event_loop_break_concurrent (pContext->handle_controller, concurrent);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t multiplexer_iocp::post (multiplexer_context_t* handle, uint32 size_vecotor, void* data_vector[])
{
    return_t ret = errorcode_t::success;

    multiplexer_iocp_context_t* pContext = (multiplexer_iocp_context_t*) handle;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (MULTIPLEXER_IOCP_CONTEXT_SIGNATURE != pContext->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        PostQueuedCompletionStatus (pContext->hIocp, (DWORD) (arch_t) data_vector[1], (ULONG_PTR) data_vector[2], (LPOVERLAPPED) data_vector[3]);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t multiplexer_iocp::setoption (multiplexer_context_t* handle, arch_t optionvalue, size_t size_optionvalue)
{
    UNREFERENCED_PARAMETER (handle);
    UNREFERENCED_PARAMETER (optionvalue);
    UNREFERENCED_PARAMETER (size_optionvalue);
    return errorcode_t::not_supported;
}

multiplexer_type_t multiplexer_iocp::type ()
{
    return mux_type_completionport;
}

}
}  // namespace
