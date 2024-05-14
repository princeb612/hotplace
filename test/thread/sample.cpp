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
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

return_t thread_routine(void* param) {
    t_shared_instance<semaphore> mtx(_mutex);

    _logger->writeln("thread started");

    _logger->writeln("wait for signal");
    mtx->wait(-1);
    _logger->writeln("caught signal");

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
    _logger->writeln("counting %d", countdown);
    msleep(1000 * countdown);

    _test_case.assert(true, __FUNCTION__, "msleep");

    _logger->writeln("send signal");
    threads.signal();

    _logger->writeln("terminating all threads (running %zi)", threads.running());
    threads.signal_and_wait_all();
    _test_case.assert(0 == threads.running(), __FUNCTION__, "all thread terminated");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    _test_case.begin("thread");
    test_signalwait_threads();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
