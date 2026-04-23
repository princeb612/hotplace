/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_loglevel.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_loglevel() {
    _test_case.begin("loglevel");

    std::map<loglevel_t, std::string> table;
    table.insert({loglevel_trace, "trace"});
    table.insert({loglevel_debug, "debug"});
    table.insert({loglevel_info, "info"});
    table.insert({loglevel_warn, "warn"});
    table.insert({loglevel_error, "error"});
    table.insert({loglevel_fatal, "fatal"});
    table.insert({loglevel_notice, "notice"});

    std::list<loglevel_t> cases;
    for (auto lvl : table) {
        cases.push_back(lvl.first);
    }

    auto dologlevel = [&](loglevel_t level, const char* message) -> void {
        bool islogged = false;
        _logger->writeln(level, [&](basic_stream& dbs) -> void {
            dbs = message;
            islogged = true;
        });
        _test_case.assert(islogged == (level >= _logger->get_loglevel()), __FUNCTION__, message);
    };
    auto doimplicitloglevel = [&](const char* message) -> void {
        bool islogged = false;
        _logger->writeln([&](basic_stream& bs) -> void {
            bs = message;
            islogged = true;
        });
        _test_case.assert(islogged == (_logger->get_implicit_loglevel() >= _logger->get_loglevel()), __FUNCTION__, message);
    };

    _logger->set_loglevel(loglevel_trace).set_implicit_loglevel(loglevel_trace);  // reset

    for (auto glevel : cases) {
        _logger->writeln(loglevel_notice, "set log level %s", table[glevel].c_str());
        _logger->set_loglevel(glevel);

        for (auto lvl : cases) {
            basic_stream bs;
            bs.printf("> current loglevel [%s] do [%s] expect [%s]", table[glevel].c_str(), table[lvl].c_str(),
                      (lvl >= _logger->get_loglevel()) ? "true" : "false");
            dologlevel(lvl, bs.c_str());
        }

        for (auto ilevel : cases) {
            _logger->writeln(loglevel_notice, "set log implicit level %s", table[ilevel].c_str());
            _logger->set_implicit_loglevel(ilevel);

            basic_stream bs;
            bs.printf("> current loglevel [%s] implicit loglevel [%s] expect [%s]", table[glevel].c_str(), table[ilevel].c_str(),
                      (_logger->get_implicit_loglevel() >= _logger->get_loglevel()) ? "true" : "false");
            doimplicitloglevel(bs.c_str());
        }
    }

    _logger->set_loglevel(loglevel_trace).set_implicit_loglevel(loglevel_trace);  // reset
}

void testcase_loglevel() { test_loglevel(); }
