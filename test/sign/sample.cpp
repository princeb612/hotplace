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

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-k", "dump keys", [](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional();
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

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void {
            std::string ct;
            std::string ev;
            auto advisor = trace_advisor::get_instance();
            advisor->get_names(category, event, ct, ev);
            _logger->write("[%s][%s]\n%.*s", ct.c_str(), ev.c_str(), (unsigned)s->size(), s->data());
        };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    _logger->consoleln("option.verbose %i", option.verbose ? 1 : 0);
    _logger->consoleln("option.dump_keys %i", option.dump_keys ? 1 : 0);

    __try2 {
        openssl_startup();

        test_hash_hmac_sign();

        test_nist_cavp_ecdsa();
        test_rfc6979_ecdsa();
        test_crypto_sign();
        test_nist_cavp_rsa();
        test_x509_sign();
        check_ecdsa_size();
        test_rsassa();
        test_dsa();
    }
    __finally2 { openssl_cleanup(); }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
