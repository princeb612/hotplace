/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/windows/semaphore.hpp>
#include <windows.h>

namespace hotplace {
namespace io {

semaphore::semaphore ()
{
    _sem = ::CreateSemaphore (nullptr, 0, 0x7ffffff, nullptr);
}

semaphore::~semaphore ()
{
    if (_sem) {
        ::CloseHandle (_sem);
        _sem = nullptr;
    }
}

uint32 semaphore::signal ()
{
    uint32 ret = errorcode_t::success;
    BOOL bRet = ::ReleaseSemaphore (_sem, 1, nullptr);

    if (FALSE == bRet) {
        ret = ::GetLastError ();
    }
    return ret;
}

uint32 semaphore::wait (unsigned msec)
{
    uint32 ret = 0;
    DWORD wait = ::WaitForSingleObject (_sem, msec);

    switch (wait) {
        case WAIT_OBJECT_0:
            break;
        case WAIT_TIMEOUT:
            ret = 1;
            break;
        case WAIT_FAILED:
            ret = 2;
            break;
    }
    return ret;
}

}
}  // namespace
