/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

const int _test_loop = 100;
const int _bucket = 10;
int _test_count = 0;
semaphore _test_signal;
semaphore _test_sleep;
typedef std::multimap<int, int> SAMPLE_MAP;
SAMPLE_MAP _data_map;

critical_section lock;

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
