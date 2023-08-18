/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_THREAD__
#define __HOTPLACE_SDK_IO_SYSTEM_THREAD__

#include <hotplace/sdk/base.hpp>
#if defined _WIN32 || defined _WIN64
    #include <windows.h>
#elif defined __linux__
    #include <pthread.h>
#endif

namespace hotplace {
namespace io {

#if defined _WIN32 || defined _WIN64
typedef HANDLE thread_t;
#elif defined __linux__
typedef pthread_t thread_t;
#endif

class thread_interface
{
public:
    virtual return_t start () = 0;
    virtual return_t join (thread_t tid) = 0;
    virtual return_t wait (unsigned msec) = 0;
    virtual thread_t gettid () = 0;
};

}
}

#if defined _WIN32 || defined _WIN64
    #include <hotplace/sdk/io/system/windows/thread.hpp>
#elif defined __linux__
    #include <hotplace/sdk/io/system/linux/thread.hpp>
#endif

#endif
