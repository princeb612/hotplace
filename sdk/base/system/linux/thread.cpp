/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/linux/thread.hpp>

namespace hotplace {

thread::thread(THREAD_CALLBACK_ROUTINE callback, void* param) : _tid(0), _callback(callback), _param(param) {}

thread::~thread() { join(); }

void* thread::thread_routine(void* param) {
    thread* this_ptr = static_cast<thread*>(param);

    this_ptr->thread_routine_implementation();

    pthread_exit(nullptr);

    return nullptr;
}

void thread::thread_routine_implementation() { _callback(_param); }

return_t thread::start() {
    return_t ret = errorcode_t::success;
    int ret_value = 0;

    if (0 == _tid) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
        ret_value = pthread_create(&_tid, &attr, thread_routine, this);
        if (0 != ret_value) {
            ret = errorcode_t::failed;
        }
        pthread_attr_destroy(&attr);
    }
    return ret;
}

return_t thread::join() {
    return_t ret = errorcode_t::success;
    ret = wait(-1);
    return ret;
}

return_t thread::wait(unsigned msec) {
    return_t ret = errorcode_t::success;
    int ret_value = 0;

#if __GLIBC_MINOR >= 3
#else
    msec = -1;
#endif

    if (_tid) {
        if ((unsigned)-1 == msec) {
            int rc = pthread_join(_tid, nullptr);
            if (0 == rc) {
                _tid = 0;
            } else {
                ret = get_lasterror(rc);
            }
        } else {
#if __GLIBC_MINOR >= 3
            TIMESPAN span = {
                0,
            };
            struct timespec ts = {
                0,
            };
            datetime_t dt;

            ts.tv_sec += msec / 1000;
            ts.tv_nsec = (msec % 1000) * 1000000;

            dt += span;
            dt.gettimespec(&ts);

            // glibc 2.3.3
            int rc = pthreadid_timedjoin_np(_tid, nullptr, &ts);
            if (0 == rc) {
                _tid = 0;
            } else {
                ret = get_lasterror(rc);
            }
#endif
        }
    }
    return ret;
}

threadid_t thread::gettid() { return _tid; }

}  // namespace hotplace
