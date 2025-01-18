#ifndef __HOTPLACE_TEST_MLFQ__
#define __HOTPLACE_TEST_MLFQ__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int verbose;
    int debug;
    int log;
    int time;
    bool test_slow_kdf;

    _OPTION() : verbose(0), debug(0), log(0), time(0), test_slow_kdf(false) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

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

    t_mlfq<int, mlfq_nonshared_binder<int>> __mfq;
};

return_t scenario(void*);
void confirm();

#endif
