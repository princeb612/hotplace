/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/io/system/signalwait_threads.hpp>

namespace hotplace {
namespace io {

signalwait_threads::signalwait_threads ()
{
    // do nothing
}

signalwait_threads::~signalwait_threads ()
{
    signal_and_wait_all ();
}

return_t signalwait_threads::set (size_t max_concurrent, SIGNALWAITTHREADS_CALLBACK_ROUTINE thread_routine,
                                  SIGNALWAITTHREADS_CALLBACK_ROUTINE signal_callback, void* thread_param)
{
    return_t ret = errorcode_t::success;

    _lock.enter ();
    if (true == _container.empty ()) {
        _capacity = max_concurrent;
        _thread_callback_routine = thread_routine;
        _signal_callback_routine = signal_callback;
        _thread_callback_param = thread_param;
    } else {
        ret = errorcode_t::not_available;
    }
    _lock.leave ();
    return ret;
}

return_t signalwait_threads::create ()
{
    return_t ret = errorcode_t::success;
    thread* thread_obj = nullptr;
    thread_info* thread_rt = nullptr;

    __try2
    {
        if (nullptr == _thread_callback_routine) {
            ret = errorcode_t::request;
            __leave2;
        }

        __try2
        {
            _lock.enter ();
            if (_container.size () < _capacity) { /* check max concurrent thread */
                __try_new_catch (thread_rt, new thread_info, ret, __leave2);
                __try_new_catch (thread_obj, new thread (thread_routine, thread_rt), ret, __leave2);

                // set members before thread starts
                thread_rt->set_thread (thread_obj);
                thread_rt->set_container (this);
                // thread starts here
                ret = thread_obj->start ();   /* CreateThread, pthread_create here */
                if (errorcode_t::success == ret) {
                    threadid_t tid = thread_obj->gettid ();
                    _container.insert (std::make_pair (tid, thread_rt));
                }
            } else {
                ret = errorcode_t::max_reached;
            }
        }
        __finally2
        {
            _lock.leave ();
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != thread_obj) {
                //thread_obj->release ();
                delete thread_obj;
            }
            if (nullptr != thread_rt) {
                delete thread_rt;
            }
        }
    }
    return ret;
}

void signalwait_threads::signal ()
{
    if (nullptr != _signal_callback_routine) {
        (*_signal_callback_routine)(_thread_callback_param);
    }
}

void signalwait_threads::signal_and_wait_all (int reserved)
{
    _lock.enter ();
    int loop = _container.size ();

    for (int i = 0; i < loop; i++) {
        signal ();
    }
    _lock.leave ();

    size_t run = 0;
    while (true) {
        _lock.enter ();
        run = running ();
        _lock.leave ();

        if (!run) {
            break;
        }

        msleep (10);
    }
}

size_t signalwait_threads::capacity ()
{
    return _capacity;
}

size_t signalwait_threads::running ()
{
    size_t size = 0;

    _lock.enter ();
    size = _container.size ();
    _lock.leave ();
    return size;
}

return_t signalwait_threads::dummy_signal (void* param)
{
    return errorcode_t::success;
}

return_t signalwait_threads::thread_routine (void* thread_param)
{
    return_t ret = errorcode_t::success;
    thread_info* thread_rt = (thread_info *) thread_param;
    signalwait_threads* container = thread_rt->get_container ();

    ret = container->thread_routine_implementation (thread_rt);

    return ret;
}

return_t signalwait_threads::thread_routine_implementation (void* param)
{
    return_t ret = errorcode_t::success;
    thread_info* thread_rt = (thread_info *) param;

    _thread_callback_routine (_thread_callback_param);

    join (thread_rt->get_thread ()->gettid ());

    return ret;
}

return_t signalwait_threads::join (threadid_t tid)
{
    return_t ret = errorcode_t::success;

    thread_info* thread_rt = nullptr;
    thread* thread = nullptr;

    _lock.enter ();
    SIGNALWAITTHREADS_MAP::iterator iter = _container.find (tid);

    if (_container.end () == iter) {
        ret = errorcode_t::not_found;
    } else {
        thread_rt = iter->second;
        thread = thread_rt->get_thread ();

        _container.erase (iter);
    }
    _lock.leave ();

    if (thread) {
        thread->join (tid); // valgrind pthread_create problem, so pthread_detach here
        delete thread;      // delete a thread object
    }
    if (thread_rt) {
        delete thread_rt; // delete after a thread destroyed
    }
    return ret;
}

}
}  // namespace
