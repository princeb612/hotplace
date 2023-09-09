/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_THREAD__
#define __HOTPLACE_SDK_BASE_SYSTEM_THREAD__

#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/callback.hpp>
#include <hotplace/sdk/base/syntax.hpp>

#if defined _WIN32 || defined _WIN64
#include <windows.h>
#elif defined __linux__
#include <pthread.h>
#endif

namespace hotplace {

#if defined _WIN32 || defined _WIN64
typedef HANDLE threadid_t;
#elif defined __linux__
typedef pthread_t threadid_t;
#endif

class thread_t
{
public:
    virtual return_t start () = 0;
    virtual return_t join (threadid_t tid) = 0;
    virtual return_t wait (unsigned msec) = 0;
    virtual threadid_t gettid () = 0;
};

}

#if defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/thread.hpp>
#elif defined __linux__
#include <hotplace/sdk/base/system/linux/thread.hpp>
#endif

#endif
