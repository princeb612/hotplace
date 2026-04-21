/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt);
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
                << t_cmdarg_t<OPTION>("-s", "test slow pbkdf2/scrypt", [](OPTION& o, char* param) -> void { o.flag_slow_kdf = true; }).optional()
                << t_cmdarg_t<OPTION>("-argon2", "test argon2d, argon2i, argon2id", [](OPTION& o, char* param) -> void { o.flag_argon2 = true; }).optional()
                << t_cmdarg_t<OPTION>("-ffdhe", "test FFDHE", [](OPTION& o, char* param) -> void { o.flag_ffdhe = true; }).optional();

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

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    __try2 {
        openssl_startup();

        testcase_advisor();

        testcase_aead_ccm();
        testcase_cbc_hmac_tls();
        testcase_cipher_encrypt();
        testcase_crypto_aead();
        testcase_crypto_encrypt();
        testcase_openssl_crypt();
        testcase_rfc3394();  // keywrap
        testcase_rfc7516();  // CBC HMAC
        testcase_rfc7539();  // chacha20, chacha20-poly1305

        testcase_openssl_hash();
        testcase_rfc4226();  // HOTP
        testcase_rfc4231();  // HMAC SHA
        testcase_rfc4493();  // CMAC
        testcase_rfc6238();  // TOTP
        testcase_transcript_hash();

        testcase_hkdf();
        testcase_rfc4615();
        testcase_rfc5869();
        if (option.flag_slow_kdf) {
            testcase_rfc6070();
            testcase_rfc7914();
        }
        if (option.flag_argon2) {
            testcase_rfc9106();
        }

        testcase_crypto_key();
        testcase_curves();
        testcase_der();
        testcase_dh();
        testcase_ec();
        testcase_hpke();
        testcase_key_dsa();
        if (option.flag_ffdhe) {
            testcase_key_ffdhe();
        }
        testcase_key_mlkem();
        testcase_key_rsa();
        testcase_keyexchange();

        testcase_pqc_dsa();
        testcase_pqc_encode();
        testcase_pqc_hybrid_kem();
        testcase_pqc_kem();

        testcase_oqs_dsa();
        testcase_oqs_encode();
        testcase_oqs_kem();

        testcase_random();

        testcase_crypto_sign();
        testcase_dsa();
        testcase_ecdsa();
        testcase_hmac();
        testcase_mldsa();
        testcase_rsassa();
        testcase_x509();
    }
    __finally2 { openssl_cleanup(); }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    _logger->consoleln("openssl 3 deprected bf, idea, seed");
    return _test_case.result();
}
