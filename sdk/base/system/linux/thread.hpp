/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_LINUX_THREAD__
#define __HOTPLACE_SDK_BASE_SYSTEM_LINUX_THREAD__

#include <pthread.h>

#include <hotplace/sdk/base/system/thread.hpp>

namespace hotplace {

#define get_thread() pthread_self()
#define get_thread_id() (arch_t) pthread_self()

/**
 * @brief thread
 */
class thread : public thread_t {
   public:
    /**
     * @brief constructor
     */
    thread(THREAD_CALLBACK_ROUTINE callback, void* param);
    /**
     * @brief destructor
     */
    virtual ~thread();

    virtual return_t start();
    virtual return_t join();

    /**
     * @brief wait
     *
     * @param unsigned msec [in]
     */
    virtual return_t wait(unsigned msec);

    virtual threadid_t gettid();

    // virtual int addref ();
    // virtual int release ();

   private:
    static void* thread_routine(void* param);
    void thread_routine_implementation();

    threadid_t _tid;
    THREAD_CALLBACK_ROUTINE _callback;
    void* _param;

    // t_shared_reference<thread> _shared;
};

}  // namespace hotplace

#endif
