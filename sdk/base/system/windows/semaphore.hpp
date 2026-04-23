/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   semaphore.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SEMAPHORE__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SEMAPHORE__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/system/semaphore.hpp>
#include <hotplace/sdk/base/system/windows/types.hpp>

namespace hotplace {

/**
 * @brief semaphore
 */
class semaphore : public semaphore_t {
   public:
    semaphore();
    semaphore(const semaphore&) = delete;
    virtual ~semaphore();

    /**
     * @brief signal
     */
    virtual return_t signal();
    /**
     * @brief wait
     *
     * @param unsigned msec [in]
     */
    virtual return_t wait(unsigned msec);

    semaphore& operator=(const semaphore&) = delete;

   protected:
    HANDLE _sem;
};

}  // namespace hotplace

#endif
