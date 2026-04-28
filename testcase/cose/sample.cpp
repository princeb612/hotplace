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
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

return_t dump_test_data(const char* text, basic_stream& diagnostic) {
    return_t ret = errorcode_t::success;
    _logger->writeln("%s %s", text ? text : "diagnostic", diagnostic.c_str());
    return ret;
}

return_t dump_test_data(const char* text, const binary_t& cbor) {
    return_t ret = errorcode_t::success;
    basic_stream bs;
    _logger->hdump(text ? text : "cbor", cbor, 32, 4);
    _logger->writeln("cbor %s", base16_encode(cbor).c_str());
    return ret;
}

void dump_crypto_key(crypto_key_object* key, void*) {
    const OPTION option = _cmdline->value();  // (*_cmdline).value () is ok
    if (option.dump_keys) {
        uint32 nid = 0;

        nidof_evp_pkey(key->get_pkey(), nid);
        _logger->writeln(ANSI_ESCAPE "1;32mnid %i kid \"%s\" alg %s use %i" ANSI_ESCAPE "0m", nid, key->get_desc().get_kid_cstr(), key->get_desc().get_alg_cstr(),
                         key->get_desc().get_use());

        basic_stream bs;
        dump_key(key->get_pkey(), &bs);
        _logger->writeln("%s", bs.c_str());
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_trace); }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-k", "dump keys", [](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional()
                << t_cmdarg_t<OPTION>("-u", "dump diagnostic", [](OPTION& o, char* param) -> void { o.dump_diagnostic = true; }).optional()
                << t_cmdarg_t<OPTION>("-b", "skip basic encoding", [](OPTION& o, char* param) -> void { o.skip_cbor_basic = true; }).optional()
                << t_cmdarg_t<OPTION>("-g", "skip self-generated message", [](OPTION& o, char* param) -> void { o.skip_gen = true; }).optional();
    (*_cmdline).parse(argc, argv);

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
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    _logger->writeln("option.verbose %i", option.verbose ? 1 : 0);
    _logger->writeln("option.dump_keys %i", option.dump_keys ? 1 : 0);
    _logger->writeln("option.skip_gen %i", option.skip_gen ? 1 : 0);

    __try2 {
        openssl_startup();

        testcase_resources();

        testcase_rfc8152();

        // part 3 https://github.com/cose-wg/Examples
        // A GitHub project has been created at <https://github.com/cose-wg/
        // Examples> that contains not only the examples presented in this
        // document, but a more complete set of testing examples as well.  Each
        // example is found in a JSON file that contains the inputs used to
        // create the example, some of the intermediate values that can be used
        // in debugging the example and the output of the example presented in
        // both a hex and a CBOR diagnostic notation format.  Some of the
        // examples at the site are designed failure testing cases; these are
        // clearly marked as such in the JSON file.  If errors in the examples
        // in this document are found, the examples on GitHub will be updated,
        // and a note to that effect will be placed in the JSON file.
        testcase_testvector_cose_examples();

        // part 4 encrypt/sign/mac
        testcase_cose();

        // part 5 CWT
        testcase_rfc8392();
    }
    __finally2 { openssl_cleanup(); }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
