/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;

struct OPTION : public CMDLINEOPTION {};
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void dump_parse_tree(asn1_runtime* runtime, const parse_tree* pt) {
    if (nullptr == pt) return;

    _logger->colorln("parse tree - re-trace");
    {
        uint32 idx = 0;
        auto lambda = [&idx](parser_action_t type, parse_treenode* node) -> return_t {
            _logger->writeln([&](basic_stream& dbs) -> void {
                valist va;
                va << idx++ << node->symbol << node->value << node->children.size();
                dbs.vaprintf("[{1:03i}] ", va);
                switch (type) {
                    case parser_action_t::shift:
                        dbs << "shift  ";
                        break;
                    case parser_action_t::reduce:
                        dbs << "reduce ";
                        break;
                    default:
                        break;
                }
                dbs.vaprintf("{2}", va);
                if ((false == node->value.empty()) && (node->symbol != node->value)) {
                    dbs.vaprintf(" ({3})", va);
                }
                if (parser_action_t::reduce == type) {
                    dbs.vaprintf(" RHS [{4}]", va);
                }
            });
            return errorcode_t::success;
        };
        parse_tree_visitor visitor(lambda);
        pt->accept(&visitor);
    }

    _logger->colorln("parser tree - graph");
    {
        auto root = pt->get_root();
        if (root) {
            basic_stream bs;
            root->print(bs);
            _logger->write(bs);
        }
    }
}
void parse_notation(asn1_runtime* runtime, const char* notation) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto asn1p = asn1_parser::get_instance();
        parse_tree pt;
        ret = asn1p->parse(runtime, notation, &pt);
        dump_parse_tree(runtime, &pt);
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "parse : %s", notation); }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline)
        << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, const char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
        << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, const char* param) -> void { o.enable_debug(); }).optional()
        << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, const char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
        << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, const char* param) -> void { o.enable_trace(loglevel_t::loglevel_trace); }).optional()
        << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, const char* param) -> void { o.enable_trace(loglevel_t::loglevel_debug); }).optional()
#endif
        << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, const char* param) -> void { o.log = 1; }).optional()
        << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, const char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());
    _logger->setcolor(bold, cyan);

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, trace_event_t event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    testcase_basic1();
    testcase_basic2();
    testcase_constraints();
    testcase_testvector_der();
    testcase_parser();
    testcase_testvector_parser();
    testcase_basic3();
    testcase_publish();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
