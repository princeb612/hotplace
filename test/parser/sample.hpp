#ifndef __HOTPLACE_TEST_PARSER__
#define __HOTPLACE_TEST_PARSER__

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

    _OPTION() : verbose(0), debug(0), log(0), time(0) {}
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_dump_testdata();
void test_parser();
void test_parser_options();
void test_parser_search();
void test_parser_compare();
void test_multipattern_search();
void test_patterns();

#endif
