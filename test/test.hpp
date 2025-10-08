/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST__
#define __HOTPLACE_TEST__

#include <math.h>
#include <signal.h>
#include <stdio.h>

#include <algorithm>
#include <deque>
#include <fstream>
#include <functional>
#include <hotplace/sdk/sdk.hpp>
#include <iostream>
#include <string>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

struct CMDLINEOPTION {
    int verbose;
    int debug;
    int trace_level;
    int log;
    int time;

    CMDLINEOPTION() : verbose(0), debug(0), trace_level(0), log(0), time(0) {}
    void enable_verbose() { verbose = 1; }
    void enable_debug() {
        verbose = 1;
        debug = 1;
    }
    void enable_trace(int level) {
        verbose = 1;
        debug = 1;
        trace_level = level;
    }
    bool is_verbose() const { return verbose > 0; }
    bool is_debug() const { return debug > 0; }
    bool is_loglevel_trace() const { return loglevel_trace == trace_level; }
    bool is_loglevel_debug() const { return loglevel_debug == trace_level; }
};

#endif
