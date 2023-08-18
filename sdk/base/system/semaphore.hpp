/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_SEMAPHORE__
#define __HOTPLACE_SDK_BASE_SYSTEM_SEMAPHORE__

#include <hotplace/sdk/base/types.hpp>
//#include <hotplace/sdk/base/error.hpp>
//#include <limits.h>
//#include <stdint.h> // int64_t
//#include <pthread.h>

namespace hotplace {

/**
 * @brief semaphore
 */
class semaphore_interface
{
public:
    /**
     * @brief signal
     */
    virtual uint32 signal () = 0;
    /**
     * @brief wait
     *
     * @param unsigned msec [in]
     */
    virtual uint32 wait (unsigned msec) = 0;
};

}  // namespace

#if defined _WIN32 || defined _WIN64
    #include <hotplace/sdk/base/system/windows/semaphore.hpp>
#elif defined __linux__
    #include <hotplace/sdk/base/system/linux/semaphore.hpp>
#endif

#endif
