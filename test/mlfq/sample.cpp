/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

const int _test_loop = 100;
const int _bucket = 10;
int _test_count = 0;
semaphore _test_signal;
semaphore _test_sleep;
typedef std::multimap <int, int> SAMPLE_MAP;
SAMPLE_MAP _data_map;

void valgrind_warning_printf (const char* msg, ...)
{
    static critical_section lock;
    va_list arg;

    va_start (arg, msg);
    lock.enter ();
    vprintf (msg, arg);
    lock.leave ();
    va_end (arg);
}

class test_scenario
{
public:
    test_scenario ()
    {
        __producer_threads.set (1, producer_scenario, producer_signal, this);
        __consumer_threads.set (1, consumer_scenario, consumer_signal, this);
    }

    ~test_scenario ()
    {
        // do nothing
    }

    void make_scenario ();
    void stop_scenario ();

protected:

    static return_t producer_scenario (void*);
    static return_t consumer_scenario (void*);
    static return_t producer_signal (void*);
    static return_t consumer_signal (void*);

    signalwait_threads __producer_threads;
    signalwait_threads __consumer_threads;
    semaphore __producer_signal;
    semaphore __consumer_signal;

    t_mlfq <int, mlfq_nonshared_binder <int> > __mfq;
};

void test_scenario::make_scenario ()
{
    __producer_threads.create ();
    __consumer_threads.create ();
}

void test_scenario::stop_scenario ()
{
    __producer_threads.signal_and_wait_all ();
    __consumer_threads.signal_and_wait_all ();
}

return_t test_scenario::producer_scenario (void* parameter)
{
    srand (time (NULL));
    test_scenario* obj = (test_scenario*) parameter;
    int i = 0;
    for (i = 0; i < _test_loop; i++) {
        return_t wait = obj->__producer_signal.wait (10);
        if (errorcode_t::success == wait) {
            break;
        }

        int pri = (uint32) rand () % _bucket;
        obj->__mfq.post (pri, new int (i));
        valgrind_warning_printf ("post %d %d\n", pri, i);
        fflush (stdout);

        _data_map.insert (std::make_pair (pri, i));

        _test_sleep.wait (1);
    }
    return 0;
}

return_t test_scenario::consumer_scenario (void* parameter)
{
    test_scenario* obj = (test_scenario*) parameter;

    while (true) {
        return_t wait = obj->__consumer_signal.wait (10);
        if (errorcode_t::success == wait) {
            break;
        }

        return_t ret = errorcode_t::success;
        int pri = 0;
        int *data = NULL;
        ret = obj->__mfq.get (&pri, &data, 1);
        if (errorcode_t::success == ret) {
            valgrind_warning_printf ("get  %d %d\n", pri, *data);
            fflush (stdout);

            if (_test_loop == ++_test_count) {
                _test_signal.signal ();
            }

            delete data;
        }

        _test_sleep.wait (30); /* data variation */
    }
    return 0;
}

return_t test_scenario::producer_signal (void* parameter)
{
    test_scenario* obj = (test_scenario*) parameter;

    obj->__producer_signal.signal ();
    return 0;
}

return_t test_scenario::consumer_signal (void* parameter)
{
    test_scenario* obj = (test_scenario*) parameter;

    obj->__consumer_signal.signal ();
    return 0;
}

return_t scenario (void*)
{
    return_t ret = errorcode_t::success;
    test_scenario test;

    test.make_scenario ();

    _test_signal.wait (-1);

    test.stop_scenario ();

    _test_case.test (ret, __FUNCTION__, "run");
    return ret;
}

void confirm ()
{
    int i = 0;

    for (i = 0; i < _bucket; i++) {
        SAMPLE_MAP::iterator iter_lower;
        SAMPLE_MAP::iterator iter_upper;
        SAMPLE_MAP::iterator iter;
        iter_lower = _data_map.lower_bound (i);
        iter_upper = _data_map.upper_bound (i);
        valgrind_warning_printf ("[%d] =>", i);
        for (iter = iter_lower; iter != iter_upper; iter++) {
            valgrind_warning_printf ("%3d ", iter->second);
        }
        valgrind_warning_printf ("\n");
    }
    fflush (stdout);
}

int main ()
{
    thread thread1 (scenario, NULL);

    thread1.start ();

    valgrind_warning_printf ("waiting\n");
    thread1.wait (-1);
    valgrind_warning_printf ("terminating\n");

    confirm ();

    _test_case.report ();
    return _test_case.result ();
}
