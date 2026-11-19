/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   semaphore.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <errno.h>
#include <sys/time.h>

#include <hotplace/sdk/base/system/linux/semaphore.hpp>

namespace hotplace {

semaphore::semaphore() { sem_init(&_sem, 0, 0); }

semaphore::~semaphore() { sem_destroy(&_sem); }

return_t semaphore::signal() {
    return_t ret = errorcode_t::success;
    int rc = sem_post(&_sem);
    ret = get_lasterror(rc);
    return ret;
}

return_t semaphore::wait(unsigned msec) {
    return_t ret = errorcode_t::success;

    if ((unsigned)-1 == msec) {
        int rc = sem_wait(&_sem);
        if (0 != rc) {
            ret = get_lasterror(errno);
        }
    } else {
        struct timeval now;
        gettimeofday(&now, nullptr);
        struct timespec ts;

        ts.tv_sec = (now.tv_sec) + (msec / 1000);
        ts.tv_nsec = (now.tv_usec * 1000) + (msec % 1000) * 1000000;
        ts.tv_sec += ts.tv_nsec / 1000000000;
        ts.tv_nsec %= 1000000000;

        int rc = sem_timedwait(&_sem, &ts);
        if (0 != rc) {
            // POSIX semaphore calls return -1 and report the actual error
            // through errno. Passing -1 to get_lasterror() misclassifies it
            // as an EAI error instead of preserving ETIMEDOUT.
            int error = errno;
            if (ETIMEDOUT == error) {
                return errorcode_t::timeout;
            } else {
                return get_lasterror(error);
            }
        }
    }
    return ret;
}

}  // namespace hotplace
