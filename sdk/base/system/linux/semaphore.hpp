/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_LINUX_SEMAPHORE__
#define __HOTPLACE_SDK_BASE_SYSTEM_LINUX_SEMAPHORE__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/system/semaphore.hpp>
#include <semaphore.h>

namespace hotplace {

/**
 * @brief semaphore
 */
class semaphore : public semaphore_t
{
public:
    semaphore ();
    ~semaphore ();

    /**
     * @brief signal
     */
    virtual uint32 signal ();
    /**
     * @brief wait
     *
     * @param unsigned msec [in]
     */
    virtual uint32 wait (unsigned msec);

protected:
    sem_t _sem;
};

}  // namespace

#endif
