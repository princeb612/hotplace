/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 *  RFC 8446
 *  RFC 5246
 *  -- RFC 8996 --
 *  RFC 4346
 *  RFC 2246
 *
 *  https://tls13.xargs.org/
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

return_t dump_record(const char* text, tls_session* session, const binary_t& bin, tls_direction_t dir, bool expect) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == text || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_records records;
        ret = records.read(session, dir, bin);

        if ((false == expect) && (success != ret)) {
            ret = expect_failure;
        }

        _test_case.test(ret, __FUNCTION__, "%s : %s", (from_client == dir) ? "C -> S" : "C <- S", text);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dump_handshake(const char* text, tls_session* session, const binary_t& bin, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == text || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_handshakes handshakes;
        ret = handshakes.read(session, dir, bin);

        _test_case.test(ret, __FUNCTION__, "%s : %s", (from_client == dir) ? "C -> S" : "C <- S", text);
    }
    __finally2 {
        // do nothing
    }
    return ret;
};

void test_keycalc(tls_session* session, tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect) {
    session->get_tls_protection().get_item(tls_secret, secret);
    _logger->writeln("> %s : %s", text, base16_encode(secret).c_str());
    _test_case.assert(secret == base16_decode(expect), __FUNCTION__, text);
};

void test_transcript_hash(tls_session* session, const binary_t& expect) {
    if (session) {
        auto hash = session->get_tls_protection().get_transcript_hash();
        if (hash) {
            binary_t tshash;
            hash->digest(tshash);
            hash->release();
            _logger->writeln(" > transcript hash");
            _logger->writeln("   %s", base16_encode(tshash).c_str());
            _test_case.assert(tshash == expect, __FUNCTION__, "transcript hash");
        }
    }
}

tls_session rfc8448_session;
tls_session rfc8448_session2;

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-cs", "cipher suite (-cs TLS_AES_256_GCM_SHA384)", [](OPTION& o, char* param) -> void { o.set_cipher_suite(param); })
                       .optional()
                       .preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void {
            // std::string ct;
            // std::string ev;
            // auto advisor = trace_advisor::get_instance();
            // advisor->get_names(category, event, ct, ev);
            // _logger->write("[%s][%s]\n%.*s", ct.c_str(), ev.c_str(), (unsigned)s->size(), s->data());
            _logger->write(s);
        };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    openssl_startup();

    test_validate();

    // https://tls13.xargs.org/
    test_tls13_xargs_org();
    // https://tls12.xargs.org/
    test_tls12_xargs_org();
    // https://github.com/syncsynchalt/illustrated-tls13/captures/
    test_capture();
    // https://dtls.xargs.org/
    test_dtls_xargs_org();

    // RFC 8448 Example Handshake Traces for TLS 1.3
    test_rfc8448_2();
    test_rfc8448_3();
    test_rfc8448_4();
    test_rfc8448_5();
    test_rfc8448_6();
    test_rfc8448_7();

    test_construct();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
