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

void test_loglevel() {
    _test_case.begin("logger");

    std::map<loglevel_t, std::string> table;
    table.insert({loglevel_trace, "trace"});
    table.insert({loglevel_debug, "debug"});
    table.insert({loglevel_info, "info"});
    table.insert({loglevel_warn, "warn"});
    table.insert({loglevel_error, "error"});
    table.insert({loglevel_fatal, "fatal"});
    table.insert({loglevel_notice, "notice"});

    std::list<loglevel_t> case1;
    std::list<loglevel_t> case2;
    case1.push_back(loglevel_trace);
    case2.push_back(loglevel_trace);
    case1.push_back(loglevel_debug);
    case2.push_back(loglevel_debug);
    case1.push_back(loglevel_info);
    case2.push_back(loglevel_info);
    case1.push_back(loglevel_warn);
    case2.push_back(loglevel_warn);
    case1.push_back(loglevel_error);
    case2.push_back(loglevel_error);
    case1.push_back(loglevel_fatal);
    case2.push_back(loglevel_fatal);
    case1.push_back(loglevel_notice);
    case2.push_back(loglevel_notice);

    auto dolog = [&](loglevel_t lvl, loglevel_t imp) -> void {
        _logger->set_loglevel(lvl).set_implicit_loglevel(imp);

        const std::string &lvlstr = table[lvl];
        const std::string &impstr = table[imp];
        std::string oper;
        if (lvl > imp) {
            oper = " > ";
        } else if (lvl == imp) {
            oper = " = ";
        } else {
            oper = " < ";
        }

        _logger->writeln(loglevel_notice, "level:%s %s implicit:%s", lvlstr.c_str(), oper.c_str(), impstr.c_str());
        _logger->writeln("> loglevel:implicit");
        _logger->writeln(loglevel_trace, "> loglevel:trace");
        _logger->writeln(loglevel_debug, "> loglevel:debug");
        _logger->writeln(loglevel_info, "> loglevel:info");
        _logger->writeln(loglevel_warn, "> loglevel:warn");
        _logger->writeln(loglevel_error, "> loglevel:error");
        _logger->writeln(loglevel_fatal, "> loglevel:fatal");
        _logger->writeln(loglevel_notice, "> loglevel:notice");
    };

    for (auto lvl : case1) {
        for (auto imp : case2) {
            dolog(lvl, imp);
        }
    }

    _logger->set_loglevel(loglevel_trace).set_implicit_loglevel(loglevel_trace);
}
