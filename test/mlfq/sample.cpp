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
t_shared_instance<logger> _logger;

const int _test_loop = 100;
const int _bucket = 10;
int _test_count = 0;
semaphore _test_signal;
semaphore _test_sleep;
typedef std::multimap<int, int> SAMPLE_MAP;
SAMPLE_MAP _data_map;

critical_section lock;

class test_scenario {
   public:
    test_scenario() {
        __producer_threads.set(1, producer_scenario, producer_signal, this);
        __consumer_threads.set(1, consumer_scenario, consumer_signal, this);
    }

    ~test_scenario() {
        // do nothing
    }

    void make_scenario();
    void stop_scenario();

   protected:
    static return_t producer_scenario(void*);
    static return_t consumer_scenario(void*);
    static return_t producer_signal(void*);
    static return_t consumer_signal(void*);

    signalwait_threads __producer_threads;
    signalwait_threads __consumer_threads;
    semaphore __producer_signal;
    semaphore __consumer_signal;

    t_mlfq<int, mlfq_nonshared_binder<int> > __mfq;
};

void test_scenario::make_scenario() {
    __producer_threads.create();
    __consumer_threads.create();
}

void test_scenario::stop_scenario() {
    __producer_threads.signal_and_wait_all();
    __consumer_threads.signal_and_wait_all();
}

return_t test_scenario::producer_scenario(void* parameter) {
    srand(time(nullptr));
    test_scenario* obj = (test_scenario*)parameter;
    int i = 0;
    for (i = 0; i < _test_loop; i++) {
        return_t wait = obj->__producer_signal.wait(1);
        if (errorcode_t::success == wait) {
            break;
        }

        int pri = (uint32)rand() % _bucket;
        obj->__mfq.post(pri, new int(i));
        _logger->writeln("post %d %d", pri, i);
        fflush(stdout);

        _data_map.insert(std::make_pair(pri, i));

        _test_sleep.wait(1);
    }
    return 0;
}

return_t test_scenario::consumer_scenario(void* parameter) {
    test_scenario* obj = (test_scenario*)parameter;

    while (true) {
        return_t wait = obj->__consumer_signal.wait(1);
        if (errorcode_t::success == wait) {
            break;
        }

        return_t ret = errorcode_t::success;
        int pri = 0;
        int* data = nullptr;
        ret = obj->__mfq.get(&pri, &data, 1);
        if (errorcode_t::success == ret) {
            _logger->writeln("get  %d %d", pri, *data);
            fflush(stdout);

            delete data;

            if (_test_loop == ++_test_count) {
                _test_signal.signal();
            }
        }

        _test_sleep.wait(3); /* data variation */
    }
    return 0;
}

return_t test_scenario::producer_signal(void* parameter) {
    test_scenario* obj = (test_scenario*)parameter;

    obj->__producer_signal.signal();
    return 0;
}

return_t test_scenario::consumer_signal(void* parameter) {
    test_scenario* obj = (test_scenario*)parameter;

    obj->__consumer_signal.signal();
    return 0;
}

return_t scenario(void*) {
    return_t ret = errorcode_t::success;
    test_scenario test;

    test.make_scenario();

    _test_signal.wait(-1);

    test.stop_scenario();

    _test_case.test(ret, __FUNCTION__, "run");
    return ret;
}

void confirm() {
    int i = 0;

    for (i = 0; i < _bucket; i++) {
        SAMPLE_MAP::iterator iter_lower;
        SAMPLE_MAP::iterator iter_upper;
        SAMPLE_MAP::iterator iter;
        iter_lower = _data_map.lower_bound(i);
        iter_upper = _data_map.upper_bound(i);
        _logger->write("[%d] =>", i);
        for (iter = iter_lower; iter != iter_upper; iter++) {
            _logger->write("%3d ", iter->second);
        }
        _logger->writeln("");
    }
    fflush(stdout);
}

int main() {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    logger_builder builder;
    builder.set(logger_t::logger_stdout, 1).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    thread thread1(scenario, nullptr);

    thread1.start();

    _logger->writeln("waiting");
    thread1.wait(-1);
    _logger->writeln("terminating");

    confirm();

    _logger->flush();

    _test_case.report(5);
    return _test_case.result();
}
