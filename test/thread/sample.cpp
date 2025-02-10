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
    int debug;
    int log;
    int time;

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

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
    threads.join();

    _logger->writeln("terminating all threads (running %zi)", threads.running());
    threads.signal_and_wait_all();
    _test_case.assert(0 == threads.running(), __FUNCTION__, "all thread terminated");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void {
            std::string ct;
            std::string ev;
            auto advisor = trace_advisor::get_instance();
            advisor->get_names(category, event, ct, ev);
            _logger->write("[%s][%s]\n%.*s", ct.c_str(), ev.c_str(), (unsigned)s->size(), s->data());
        };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    _test_case.begin("thread");
    test_signalwait_threads();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
