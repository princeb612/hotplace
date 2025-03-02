#ifndef __HOTPLACE_TEST_QPACK__
#define __HOTPLACE_TEST_QPACK__

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

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

extern unsigned int count_evict_encoder;
extern unsigned int count_evict_decoder;

void test_expect(binary_t& bin, const char* expect, const char* text, ...);
void test_dump(binary_t& bin, const char* text, ...);
void debug_qpack_encoder(trace_category_t, uint32 event);
void debug_qpack_decoder(trace_category_t, uint32 event);

void test_rfc9204_b();
void test_zero_capacity();
void test_tiny_capacity();
void test_small_capacity();

#endif
