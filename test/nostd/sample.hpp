#ifndef __HOTPLACE_TEST_NOSTD__
#define __HOTPLACE_TEST_NOSTD__

#include <math.h>
#include <stdio.h>

#include <deque>
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

void test_btree();
void test_avl_tree();
void test_vector();
void test_list();
void test_pq();
void test_find_lessthan_or_equal();

#endif
