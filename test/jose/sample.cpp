/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void print_text(const char* text, ...) {
    console_color concolor;
    va_list ap;

    basic_stream bs;

    bs << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::green);

    va_start(ap, text);
    bs.vprintf(text, ap);
    va_end(ap);

    bs << concolor.turnoff();

    _logger->writeln(bs);
}

void dump(const char* text, const std::string& value) {
    if (text) {
        const OPTION& option = _cmdline->value();
        if (option.verbose) {
            _logger->writeln("%s\n%s", text, value.c_str());
        }
    }
}

void dump_b64url(const char* text, const byte_t* addr, size_t size) {
    if (text && addr) {
        const OPTION& option = _cmdline->value();
        if (option.verbose) {
            _logger->writeln("%s\n  %s", text, base64_encode(addr, size, encoding_t::encoding_base64url).c_str());
        }
    }
}

void dump_b64url(const char* text, const binary_t& bin) {
    if (text) {
        const OPTION& option = _cmdline->value();
        if (option.verbose) {
            _logger->writeln("%s\n  %s", text, base64_encode(bin, encoding_t::encoding_base64url).c_str());
        }
    }
}

void dump2(const char* text, std::string const str) {
    if (text) {
        const OPTION& option = _cmdline->value();
        if (option.verbose) {
            _logger->dump(str, 16, 2);
        }
    }
}

void dump2(const char* text, binary_t const bin) {
    if (text) {
        const OPTION& option = _cmdline->value();
        if (option.verbose) {
            _logger->dump(bin, 16, 2);
        }
    }
}

void dump2(const char* text, const byte_t* addr, size_t size) {
    if (text && addr) {
        const OPTION& option = _cmdline->value();
        if (option.verbose) {
            _logger->dump(addr, size, 16, 2);
        }
    }
}

void dump_elem(const binary_t& source) {
    const OPTION& option = _cmdline->value();
    if (option.verbose) {
        basic_stream bs;
        bs << "[";
#if __cplusplus >= 201103L  // c++11
        for_each(source.begin(), source.end(), [&](byte_t c) { bs.printf("%i,", c); });
#else
        for (binary_t::iterator iter = source.begin(); iter != source.end(); iter++) {
            byte_t c = *iter;
            bs.printf("%i,", c);
        }
#endif
        bs << "]";
        _logger->writeln(bs);
    }
}

void dump_elem(const std::string& source) {
    const OPTION& option = _cmdline->value();
    if (option.verbose) {
        basic_stream bs;
        bs << "[";
#if __cplusplus >= 201103L  // c++11
        for_each(source.begin(), source.end(), [&](byte_t c) { bs.printf("%i,", c); });
#else
        for (std::string::iterator iter = source.begin(); iter != source.end(); iter++) {
            byte_t c = *iter;
            bs.printf("%i,", c);
        }
#endif
        bs << "]";
        _logger->writeln(bs);
    }
}

void dump_crypto_key(crypto_key_object* key, void*) {
    const OPTION option = _cmdline->value();  // (*_cmdline).value () is ok

    if (option.dump_keys) {
        uint32 nid = 0;

        nidof_evp_pkey(key->get_pkey(), nid);
        _logger->writeln("nid %i kid %s alg %s use %i", nid, key->get_desc().get_kid_cstr(), key->get_desc().get_alg_cstr(), key->get_desc().get_use());

        basic_stream bs;
        dump_key(key->get_pkey(), &bs);
        _logger->writeln("%s", bs.c_str());
    }
}

return_t hash_stream(const char* algorithm, byte_t* stream, size_t size, binary_t& value) {
    return_t ret = errorcode_t::success;

    __try2 {
        value.clear();

        if (nullptr == algorithm || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        hash_context_t* handle = nullptr;
        openssl_hash openssl;
        ret = openssl.open(&handle, algorithm, nullptr, 0);
        if (errorcode_t::success == ret) {
            openssl.hash(handle, stream, size, value);
            openssl.close(handle);
        }
    }
    __finally2 {}
    return ret;
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
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    _logger->writeln("option.dump_keys %i", option.dump_keys ? 1 : 0);

    openssl_startup();

    test_basic();

    _test_case.begin("RFC 7515");

    test_rfc7515_A1();
    test_rfc7515_HS();
    test_rfc7515_A2();
    test_rfc7515_A3();
    test_rfc7515_A4();
    test_rfc7515_A5();
    test_rfc7515_A6();
    test_rfc7515_A7();

    _test_case.begin("RFC 7515 PEM");
    test_rfc7515_bypem();
    _test_case.begin("RFC 7515 key generation");
    test_rfc7515_bykeygen();

    _test_case.begin("key matching");
    key_match_test();

    _test_case.begin("RFC 7516");

    test_rfc7516_A1_test();
    test_rfc7516_A1();  // RSAES-OAEP and AES GCM

    test_rsa_oaep_256();
    test_rsa_oaep();

    test_rfc7516_A2();  // RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
    test_rfc7516_A3();  // AES Key Wrap and AES_128_CBC_HMAC_SHA_256
    test_rfc7516_A4();  // Example JWE Using General JWE JSON Serialization

    test_rfc7516_B();

    _test_case.begin("RFC 7517");
    test_jwk();
    test_rfc7517_C();  // RFC 7517 Appendix C.

    _test_case.begin("RFC 7518");
    test_rfc7518_RSASSA_PSS();  // test
    test_ecdh();
    test_rfc7518_C();

    _test_case.begin("RFC 7520");
    test_rfc7520();
    test_rfc7520_6_nesting_sig_and_enc();

    test_jwe_flattened();
    test_jwe_json(jwe_t::jwe_a128cbc_hs256);
    test_jwe_json(jwe_t::jwe_a192cbc_hs384);
    test_jwe_json(jwe_t::jwe_a256cbc_hs512);
    test_jwe_json(jwe_t::jwe_a128gcm);
    test_jwe_json(jwe_t::jwe_a192gcm);
    test_jwe_json(jwe_t::jwe_a256gcm);

    _test_case.begin("RFC 7638");
    test_jwk_thumbprint();

    _test_case.begin("RFC 8037");
    test_rfc8037();
    test_okp();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(20);
    _cmdline->help();
    return _test_case.result();
}
