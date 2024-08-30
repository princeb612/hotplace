/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/windows/semaphore.hpp>

namespace hotplace {

semaphore::semaphore() { _sem = ::CreateSemaphore(nullptr, 0, 0x7ffffff, nullptr); }

semaphore::~semaphore() {
    if (_sem) {
        ::CloseHandle(_sem);
        _sem = nullptr;
    }
}

return_t semaphore::signal() {
    return_t ret = errorcode_t::success;
    BOOL bRet = ::ReleaseSemaphore(_sem, 1, nullptr);
    if (FALSE == bRet) {
        ret = ::GetLastError();
    }
    return ret;
}

return_t semaphore::wait(unsigned msec) {
    return_t ret = errorcode_t::success;
    DWORD wait = ::WaitForSingleObject(_sem, msec);

    switch (wait) {
        case WAIT_OBJECT_0:
            break;
        case WAIT_TIMEOUT:
            ret = errorcode_t::timeout;
            break;
        case WAIT_FAILED:
            ret = GetLastError();
            break;
        case WAIT_ABANDONED:
            ret = errorcode_t::abandoned;
            break;
    }
    return ret;
}

}  // namespace hotplace
