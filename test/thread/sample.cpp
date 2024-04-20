/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;
t_shared_instance<semaphore> _mutex;

void valgrind_safe_printf(const char* msg, ...) {
    // try to avoid valgrind warnings, share lock (printf and test_case)
    _test_case.lock();

    va_list arg;
    printf("[%08lx] ", get_thread_id());
    va_start(arg, msg);
    vprintf(msg, arg);
    va_end(arg);
    printf("\n");

    _test_case.unlock();
}

return_t thread_routine(void* param) {
    t_shared_instance<semaphore> mtx(_mutex);

    valgrind_safe_printf("thread startedn");

    valgrind_safe_printf("wait for signal");
    mtx->wait(-1);
    valgrind_safe_printf("caught signal");

    return errorcode_t::success;
}

return_t thread_signal(void* param) {
    t_shared_instance<semaphore> mtx(_mutex);

    mtx->signal();
    return errorcode_t::success;
}

void test_signalwait_threads() {
    return_t test = errorcode_t::success;

    signalwait_threads threads;

    _mutex.make_share(new semaphore);

    int count = 4;
    threads.set(count, thread_routine, thread_signal, nullptr);
    for (int i = 0; i < count; i++) {
        threads.create();
    }
    _test_case.assert(true, __FUNCTION__, "threads created");

    test = threads.create();  // fail
    _test_case.assert(errorcode_t::max_reached == test, __FUNCTION__, "test max concurrent threads reached");

    int countdown = 3;
    valgrind_safe_printf("counting %d", countdown);
    msleep(1000 * countdown);

    _test_case.assert(true, __FUNCTION__, "msleep");

    valgrind_safe_printf("send signal");
    threads.signal();

    valgrind_safe_printf("terminating all threads (running %zi)", threads.running());
    threads.signal_and_wait_all();
    _test_case.assert(0 == threads.running(), __FUNCTION__, "all thread terminated");
}

int main() {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _test_case.begin("thread");
    test_signalwait_threads();

    _test_case.report(5);
    return _test_case.result();
}
