/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_SIGNALWAITTHREADS__
#define __HOTPLACE_SDK_BASE_SYSTEM_SIGNALWAITTHREADS__

#include <map>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/thread.hpp>

namespace hotplace {

/**
 * @brief register thread-termination signal_routine and wait a signal
 * @remarks
 */
typedef return_t (*SIGNALWAITTHREADS_CALLBACK_ROUTINE)(void*);

class signalwait_threads;
class thread_info {
   public:
    thread_info() {}

    void set_thread(thread* obj) { _thread = obj; }
    void set_container(signalwait_threads* container) { _container = container; }

    thread* get_thread() { return _thread; }
    signalwait_threads* get_container() { return _container; }

   protected:
    thread* _thread;
    signalwait_threads* _container;
};

/**
 *  signalwait_threads threads;
 *
 *  int count = 4; // ex. 2 * (nr of cpu)
 *  threads.set (count, thread_routine, thread_signal, nullptr);
 *  for (int i = 0; i < count; i++) {
 *      threads.create ();
 *  }
 *
 *  // stop 1 thread
 *  threads.signal ();
 *
 *  // stop all threads
 *  threads.signal_and_wait_all ();
 */
class signalwait_threads {
   public:
    signalwait_threads();
    ~signalwait_threads();

    /**
     * @brief call before create method.
     * @param   size_t                      max_concurrent  [IN] limit
     * @param   signalwait_thread_routine   thread_routine  [IN] thread.handler
     * @param   signalwait_thread_routine   signal_callback [IN] stop thread
     * @param   void*                       thread_param    [IN] parameter
     * @return error code (see error.hpp)
     * @remarks if a threads running, it fails.
     */
    return_t set(size_t max_concurrent, SIGNALWAITTHREADS_CALLBACK_ROUTINE thread_routine, SIGNALWAITTHREADS_CALLBACK_ROUTINE signal_callback,
                 void* thread_param);
    /**
     * @brief create a thread
     * @return error code (see error.hpp)
     * @remarks
     *          if a maximum number of threads running, it returns errorcode_t::max_reached.
     */
    return_t create();
    /**
     * @brief call (*signal_callback)(thread_param)
     */
    void join();
    /**
     * @brief stop all
     * @param   int     reserved    [INOPT] 0
     */
    void signal_and_wait_all(int reserved = 0);
    /**
     * @brief limit
     */
    size_t capacity();
    /**
     * @brief number of threads running
     */
    size_t running();
    /**
     * @brief dummy signal handler
     * @return error code (see error.hpp)
     * @remarks
     *          do nothing
     */
    static return_t dummy_signal(void* param);

   protected:
    /**
     * @brief thread routine
     */
    static return_t thread_routine(void* thread_param);
    return_t thread_routine_implementation(void* param);
    /**
     * @brief join
     * @param threadid_t tid
     * @return error code (see error.hpp)
     */
    return_t ready_to_join(threadid_t tid);
    void join_signaled();

    size_t _capacity;                                             ///<< max number of concurrent thread
    SIGNALWAITTHREADS_CALLBACK_ROUTINE _thread_callback_routine;  ///<< thread
    SIGNALWAITTHREADS_CALLBACK_ROUTINE _signal_callback_routine;  ///<< signal handler
    void* _thread_callback_param;                                 ///<< parameter

    typedef std::map<threadid_t, thread_info*> SIGNALWAITTHREADS_MAP;
    critical_section _lock;
    SIGNALWAITTHREADS_MAP _container;
    SIGNALWAITTHREADS_MAP _readytojoin;
    semaphore _sem;
};

}  // namespace hotplace

#endif
