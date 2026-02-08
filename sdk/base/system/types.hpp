/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_TYPES__
#define __HOTPLACE_SDK_BASE_SYSTEM_TYPES__

#include <functional>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

#if defined __linux__
#define DLSYM(handle, nameof_api, func_ptr) *(void **)(&func_ptr) = dlsym(handle, nameof_api)
#define TRYDLSYM(handle, nameof_api, func_ptr, branch_if_fail) \
    {                                                          \
        DLSYM(handle, nameof_api, func_ptr);                   \
        char *error = nullptr;                                 \
        if (nullptr != (error = dlerror())) {                  \
            branch_if_fail;                                    \
        }                                                      \
    }
#elif defined _WIN32 || defined _WIN64
#define DLSYM(handle, nameof_api, func_ptr) *(void **)(&func_ptr) = (void *)GetProcAddress((HMODULE)handle, nameof_api)
#define TRYDLSYM(handle, nameof_api, func_ptr, branch_if_fail) \
    {                                                          \
        DLSYM(handle, nameof_api, func_ptr);                   \
        if (nullptr == func_ptr) {                             \
            branch_if_fail;                                    \
        }                                                      \
    }
#endif

class critical_section;
class datetime;
class semaphore;
class signalwait_threads;
class thread;

}  // namespace hotplace

#endif
