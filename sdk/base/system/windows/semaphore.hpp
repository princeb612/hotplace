/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SEMAPHORE__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SEMAPHORE__

#include <sdk/base/error.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/windows/types.hpp>

namespace hotplace {

/**
 * @brief semaphore
 */
class semaphore : public semaphore_t {
   public:
    semaphore();
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

   protected:
    HANDLE _sem;
};

}  // namespace hotplace

#endif
