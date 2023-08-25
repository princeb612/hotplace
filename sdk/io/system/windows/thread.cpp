/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/system/windows/thread.hpp>

namespace hotplace {
namespace io {

thread::thread (THREAD_CALLBACK_ROUTINE callback, void* param)
    : _tid (nullptr),
    _callback (callback),
    _param (param)
{
}

thread::~thread ()
{
    join (_tid);
}

DWORD thread::thread_routine (void* param)
{
    thread* this_ptr = static_cast<thread*>(param);

    this_ptr->thread_routine_implementation ();

    return 0;
}

void thread::thread_routine_implementation ()
{
    _callback (_param);
}

return_t thread::start ()
{
    return_t ret = errorcode_t::success;

    if (0 == _tid) {
        DWORD id = 0;
        _tid = CreateThread (nullptr, 4096, thread_routine, this, 0, &id);
        if (nullptr == _tid) {
            ret = GetLastError ();
        }
    }
    return ret;
}

return_t thread::join (threadid_t tid)
{
    return_t ret = errorcode_t::success;

    if (_tid) {
        CloseHandle (_tid);
        _tid = nullptr;
    }
    return ret;
}

return_t thread::wait (unsigned msec)
{
    return_t ret = errorcode_t::success;

    if (_tid) {
        int wait = WaitForSingleObject (_tid, msec);
        switch (wait) {
            case WAIT_OBJECT_0:
                break;
            default:
                ret = 1;
                break;
        }
    }

    return ret;
}

threadid_t thread::gettid ()
{
    return _tid;
}

}
}  // namespace
