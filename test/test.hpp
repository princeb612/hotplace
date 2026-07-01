/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   test.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TEST__
#define __HOTPLACE_TEST_TEST__

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
#define YAML_CPP_STATIC_DEFINE
#include <yaml-cpp/yaml.h>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;

struct CMDLINEOPTION {
    int verbose;
    int debug;
    loglevel_t trace_level;
    int log;
    int time;

    CMDLINEOPTION() : verbose(0), debug(0), trace_level(loglevel_t::default_loglevel), log(0), time(0) {}
    void enable_verbose() { verbose = 1; }
    void enable_debug() {
        verbose = 1;
        debug = 1;
    }
    void enable_trace(int level) {
        verbose = 1;
        debug = 1;
        trace_level = loglevel_helper::to_loglevel(level);
    }
    void enable_trace(loglevel_t level) {
        verbose = 1;
        debug = 1;
        trace_level = level;
    }
    bool is_verbose() const { return verbose > 0; }
    bool is_debug() const { return debug > 0; }
    bool is_loglevel_trace() const { return loglevel_t::loglevel_trace == trace_level; }
    bool is_loglevel_debug() const { return loglevel_t::loglevel_debug == trace_level; }
};

class yaml_testcase {
   public:
    yaml_testcase() {}

    yaml_testcase& add(const std::string& schema, std::function<void(const YAML::Node&, const YAML::Node&)> func) {
        if (func) {
            critical_section_guard guard(_lock);
            _dispatcher.emplace(schema, func);
        }
        return *this;
    }

    void run(const char* filename) {
        if (nullptr == filename) return;

        critical_section_guard guard(_lock);

        YAML::Node testvector = YAML::LoadFile(filename);
        auto examples = testvector["testvector"];
        if (examples && examples.IsSequence()) {
            for (const auto& example : examples) {
                auto text_example = example["example"].as<std::string>("");

                _test_case.begin(text_example);
                _logger->writeln("example: %s", text_example.c_str());

                auto schema = example["schema"].as<std::string>("");
                auto items = example["items"];

                auto iter = _dispatcher.find(schema);
                if (_dispatcher.end() == iter) {
                    _test_case.test(errorcode_t::not_found, __FUNCTION__, "[%s] bad format - reason: schema");
                } else {
                    auto& func = iter->second;
                    func(example, items);
                }
            }
        }
    }

   protected:
    critical_section _lock;
    typedef std::map<std::string, std::function<void(const YAML::Node&, const YAML::Node&)>> dispatcher_t;
    dispatcher_t _dispatcher;
};

#endif
