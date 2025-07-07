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

#include <sdk/base/error.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief semaphore
 */
class semaphore_t {
   public:
    /**
     * @brief signal
     */
    virtual return_t signal() = 0;
    /**
     * @brief wait
     *
     * @param unsigned msec [in]
     */
    virtual return_t wait(unsigned msec) = 0;
};

}  // namespace hotplace

#if defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/semaphore.hpp>
#elif defined __linux__
#include <sdk/base/system/linux/semaphore.hpp>
#endif

#endif
