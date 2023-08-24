/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SEMAPHORE__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SEMAPHORE__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/system/semaphore.hpp>

namespace hotplace {
namespace io {

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
    HANDLE _sem;
};

}
}  // namespace

#endif
