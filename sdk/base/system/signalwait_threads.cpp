/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/signalwait_threads.hpp>

namespace hotplace {

signalwait_threads::signalwait_threads() {}

signalwait_threads::~signalwait_threads() { signal_and_wait_all(); }

return_t signalwait_threads::set(size_t max_concurrent, SIGNALWAITTHREADS_CALLBACK_ROUTINE thread_routine, SIGNALWAITTHREADS_CALLBACK_ROUTINE signal_callback,
                                 void* thread_param) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    if (true == _container.empty()) {
        _capacity = max_concurrent;
        _thread_callback_routine = thread_routine;
        _signal_callback_routine = signal_callback;
        _thread_callback_param = thread_param;
    } else {
        ret = errorcode_t::not_available;
    }
    return ret;
}

return_t signalwait_threads::create() {
    return_t ret = errorcode_t::success;
    thread* thread_obj = nullptr;
    thread_info* thread_rt = nullptr;

    __try2 {
        if (nullptr == _thread_callback_routine) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        critical_section_guard guard(_lock);

        if (_container.size() < _capacity) { /* check max concurrent thread */
            __try_new_catch(thread_rt, new thread_info, ret, __leave2);
            __try_new_catch(thread_obj, new thread(thread_routine, thread_rt), ret, __leave2);

            // set members before thread starts
            thread_rt->set_thread(thread_obj);
            thread_rt->set_container(this);
            // thread starts here
            ret = thread_obj->start(); /* CreateThread, pthread_create here */
            if (errorcode_t::success == ret) {
                threadid_t tid = thread_obj->gettid();
                _container.insert(std::make_pair(tid, thread_rt));
            }
        } else {
            ret = errorcode_t::max_reached;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != thread_obj) {
                // thread_obj->release ();
                delete thread_obj;
            }
            if (nullptr != thread_rt) {
                delete thread_rt;
            }
        }
    }
    return ret;
}

void signalwait_threads::join() {
    size_t run = running();
    if (run && _signal_callback_routine) {
        (*_signal_callback_routine)(_thread_callback_param);
        join_signaled();
    }
}

void signalwait_threads::join_signaled() {
    return_t ret = errorcode_t::success;
    ret = _sem.wait(-1);
    if (errorcode_t::success == ret) {
        thread_info* thread_context = nullptr;
        thread* thread = nullptr;

        {
            critical_section_guard guard(_lock);
            if (_readytojoin.size()) {
                auto iter = _readytojoin.begin();
                thread_context = iter->second;
                thread = thread_context->get_thread();
                _readytojoin.erase(iter);
            }
        }

        if (thread) {
            thread->join();
            delete thread;
            delete thread_context;
        }
    }
}

void signalwait_threads::signal_and_wait_all(int reserved) {
    size_t loop = running();
    for (auto i = 0; i < loop; i++) {
        join();
    }
}

size_t signalwait_threads::capacity() { return _capacity; }

size_t signalwait_threads::running() {
    size_t size = 0;

    critical_section_guard guard(_lock);
    size = _container.size();
    return size;
}

return_t signalwait_threads::dummy_signal(void* param) { return errorcode_t::success; }

return_t signalwait_threads::thread_routine(void* thread_param) {
    return_t ret = errorcode_t::success;
    thread_info* thread_rt = (thread_info*)thread_param;
    signalwait_threads* container = thread_rt->get_container();

    ret = container->thread_routine_implementation(thread_rt);

    return ret;
}

return_t signalwait_threads::thread_routine_implementation(void* param) {
    return_t ret = errorcode_t::success;
    thread_info* thread_rt = (thread_info*)param;

    _thread_callback_routine(_thread_callback_param);

    ready_to_join(thread_rt->get_thread()->gettid());

    return ret;
}

return_t signalwait_threads::ready_to_join(threadid_t tid) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    SIGNALWAITTHREADS_MAP::iterator iter = _container.find(tid);
    if (_container.end() == iter) {
        throw exception(errorcode_t::unexpected);
    } else {
        _readytojoin.insert({iter->first, iter->second});
        _container.erase(iter);
        _sem.signal();
    }

    return ret;
}

}  // namespace hotplace
