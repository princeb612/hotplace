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

void dump_parse_tree(const parse_tree* pt) {
    {
        _logger->colorln("parse tree - re-trace");
        _logger->write([&pt](basic_stream& dbs) -> void { pt->print(0, dbs); });
    }
    {
        _logger->colorln("parse tree - graph");
        _logger->write([&pt](basic_stream& dbs) -> void { pt->print(1, dbs); });
    }
}

void parse_notation(asn1_runtime* runtime, const char* notation) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        asn1_parser parser;
        parse_tree pt;
        ret = parser.parse(notation, &pt);
        dump_parse_tree(&pt);
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "parse : %s", notation); }
}

void parse_reconst_notation(asn1_runtime* runtime, const char* notation, const char* expect) {
    if (nullptr == notation) return;

    // parse
    parse_tree pt;
    asn1_parser parser;
    parser.parse(notation, &pt);
    dump_parse_tree(&pt);

    // reconstruction
    basic_stream bs;
    asn1_build_resultset result;
    auto publisher = asn1_resource::get_instance()->get_publisher();
    publisher->build(&pt, result);
    if (result.object) {
        result.object->publish(&bs);
    }
    _logger->writeln("parse and publish %s", bs.c_str());
    if (expect)
        _test_case.assert(bs == expect, __FUNCTION__, "test %s", notation);  // output the input notation for the unittest line
    else
        _test_case.assert(bs == notation, __FUNCTION__, "test %s", notation);
}

return_t prepare_lexer_asn1(lexical_analyzer& lexer) {
    lexer.clear().prepare();
    auto resource = parser_resource::get_instance();
    resource->for_each(resource_type_t::token_type_asn1, [&lexer](uint32 token, const std::string& name) -> void { lexer.add_token(name, token); });
    lexer.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);
    return errorcode_t::success;
}

return_t prepare_lexer_asn1_usertype(lexical_analyzer& lexer) {
    prepare_lexer_asn1(lexer);
    lexer.get_config().set("handle_lvalue_usertype", 1).set("handle_asn1parameterized", 1);
    return errorcode_t::success;
}

void test_asn1parser(parser_t& parser, const char* text, const char* input, uint16 flags) {
    lexical_analyzer lexer;
    prepare_lexer_asn1_usertype(lexer);
    return test_asn1parser(lexer, parser, text, input, flags);
}

void test_asn1parser(lexical_analyzer& lexer, parser_t& parser, const char* text, const char* input, uint16 flags) {
    return_t ret = errorcode_t::success;
    std::vector<parser_token> tokens;

    lexical_context context;

    if (FLAG_DUMMY_POC_TOKEN == flags) {
        lexer.add_token("....", token_ellipsis);  // tokens replaced via block reduction for the PoC
    }

    lexer.parse(context, input);

    size_t cnt = 0;
    auto lambda = [&](const token_description* desc) -> bool {
        bool ret = true;
        const auto& type = desc->type;
        std::string token(desc->p, desc->size);
        switch (type) {
            case token_lvalue: {
                tokens.push_back({token_identifier, token});
            } break;
            case token_comments:
                break;
            default: {
                tokens.push_back({type, token});
                break;
            }
        }
        if (token_comments != type) {
            _logger->writeln("[%03zu] line %zi type %d(%s) index %d pos %zi len %zi line %zi (%.*s)", cnt, desc->line, desc->type, lexer.nameof_token(desc->type).c_str(),
                             desc->index, desc->pos, desc->size, desc->line, desc->size, desc->p);
            cnt = tokens.size();
        }
        return ret;
    };
    context.for_each(lambda);
    tokens.push_back({token_eof, "$"});

    parse_tree pt;
    ret = parser.parse(tokens, &pt);

    dump_parse_tree(&pt);

    _logger->writeln("parsing %s.", (errorcode_t::success == ret) ? "completed successfully" : "failed");
    _test_case.test(ret, __FUNCTION__, "parse %s", text);
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

    _test_case.begin("LALR(1) parser - ASN.1 for Notation");
    auto& p1 = get_lalr1_parser_asn1_notation_by_build();
    _test_case.assert(p1.ready(), __FUNCTION__, "LALR(1) parser build table for Notation");
    _test_case.begin("LALR(1) parser - ASN.1 for Notation (imported)");
    auto& p2 = get_lalr1_parser_asn1_notation_by_import();
    _test_case.assert(p2.ready(), __FUNCTION__, "LALR(1) parser import table for Notation");
    _test_case.begin("GLR parser - ASN.1 for All-in-One");
    auto& p3 = get_glr_parser_asn1_by_build();
    _test_case.assert(p3.ready(), __FUNCTION__, "GLR parser build table for Notation, Module, Parameterized, Information Object Class");
    _test_case.begin("GLR parser - ASN.1 for All-in-One (imported)");
    auto& p4 = get_glr_parser_asn1_by_import();
    _test_case.assert(p4.ready(), __FUNCTION__, "GLR parser import table for Notation, Module, Parameterized, Information Object Class");

    testcase_basic1();
    testcase_basic2();
    testcase_constraints();
    testcase_testvector_der();

    testcase_parser();
    testcase_testvector_parser();
    testcase_publish();
    testcase_basic3();
    testcase_loader();

    _logger->flush();

    _test_case.report(30);
    _cmdline->help();
    return _test_case.result();
}
