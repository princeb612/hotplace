/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

t_shared_instance<semaphore> _mutex;

return_t thread_routine(void *param) {
    _logger->writeln("thread started");

    _logger->writeln("wait for signal");
    _mutex->wait(-1);
    _logger->writeln("caught signal");

    return errorcode_t::success;
}

return_t thread_signal(void *param) {
    _mutex->signal();
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
    _logger->writeln("counting %d", countdown);
    msleep(1000 * countdown);

    _test_case.assert(true, __FUNCTION__, "msleep");

    _logger->writeln("send signal");
    threads.join();

    _logger->writeln("terminating all threads (running %zi)", threads.running());
    threads.signal_and_wait_all();
    _test_case.assert(0 == threads.running(), __FUNCTION__, "all thread terminated");
}

void testcase_signalwait_threads() { test_signalwait_threads(); }
