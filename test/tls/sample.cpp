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

return_t dump_record(const char* text, tls_session* session, tls_direction_t dir, const binary_t& bin, bool expect) {
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

return_t dump_handshake(const char* text, tls_session* session, tls_direction_t dir, const binary_t& bin) {
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
    secret = session->get_tls_protection().get_secrets().get(tls_secret);
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

void direction_string(tls_direction_t dir, int send, std::string& s) {
    s += "{";
    if (from_client == dir) {
        if (0 == send) {
            s += "*";
        }
        s += "client->server";
        if (send) {
            s += "*";
        }
    } else {
        if (send) {
            s += "*";
        }
        s += "client<-server";
        if (0 == send) {
            s += "*";
        }
    }
    s += "}";
}

void do_cross_check_keycalc(tls_session* clisession, tls_session* svrsession, tls_secret_t secret, const char* secret_name) {
    auto& client_protection = clisession->get_tls_protection();
    auto& server_protection = svrsession->get_tls_protection();

    auto client_secret = client_protection.get_secrets().get(secret);
    auto server_secret = server_protection.get_secrets().get(secret);

    _logger->writeln("client secret %s (internal 0x%04x) (session %p) %s", secret_name, secret, svrsession, base16_encode(client_secret).c_str());
    _logger->writeln("server secret %s (internal 0x%04x) (session %p) %s", secret_name, secret, clisession, base16_encode(server_secret).c_str());

    _test_case.assert(client_secret == server_secret, __FUNCTION__, "cross-check secret %s", secret_name);
}

void play_pcap(tls_session* session, const pcap_testvector* testvector, size_t size) {
    bool has_fatal = false;

    auto lambda_test_fatal_alert = [&](uint8 level, uint8 desc) -> void {
        if (tls_alertlevel_fatal == level) {
            if (tls_alertdesc_certificate_unknown != desc) {
                has_fatal = true;
            }
        }
    };

    for (auto i = 0; i < size; i++) {
        const pcap_testvector* item = testvector + i;

        binary_t bin_record = std::move(base16_decode_rfc(item->record));
        dump_record(item->desc, session, item->dir, bin_record);

        session->get_alert(item->dir, lambda_test_fatal_alert);
        if (has_fatal) {
            _test_case.test(failed, __FUNCTION__, "fatal alert");
            break;
        }
    }
}

return_t construct_record_fragmented(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        record->addref();

        ret = record->get_session()->get_dtls_record_publisher().publish(record, dir, func);

        record->release();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t construct_record_fragmented(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto lambda = [&](tls_record* record) -> return_t {
            record->addref();
            ret = record->get_session()->get_dtls_record_publisher().publish(record, dir, func);
            record->release();
            return ret;
        };
        ret = records->for_each(lambda);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.trace_level = atoi(param); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.trace_level = 0; }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.trace_level = 2; }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-k", "keylog", [](OPTION& o, char* param) -> void { o.keylog = 1; }).optional()
                << t_cmdarg_t<OPTION>("-c", "dump clienthello (base16 stream)",
                                      [](OPTION& o, char* param) -> void {
                                          o.verbose = 1;
                                          o.debug = 1;
                                          o.clienthello = std::move(base16_decode_rfc(param));
                                      })
                       .optional()
                       .preced();
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

    auto lambda = [&](const char* line) -> void { _logger->writeln(line); };
    if (option.keylog) {
        auto sslkeylog = sslkeylog_exporter::get_instance();
        sslkeylog->set(lambda);
    }

    openssl_startup();

    if (option.clienthello.empty()) {
#if defined DEBUG
        auto lambda = [&](const char* line) -> void { _logger->writeln(line); };
        if (check_trace_level(loglevel_debug) && istraceable()) {
            auto sslkeylog = sslkeylog_exporter::get_instance();
            sslkeylog->set(lambda);
        }
#endif

        {
            // resource validation
            test_validate();
        }

        {
            // https://tls13.xargs.org/
            test_tls13_xargs_org();
            // https://tls12.xargs.org/
            test_tls12_xargs_org();
            // https://dtls.xargs.org/
            test_dtls_xargs_org();

            // RFC 8448 Example Handshake Traces for TLS 1.3
            test_rfc8448_2();

            tls_session rfc8448_session;

            test_rfc8448_3(&rfc8448_session);

            test_rfc8448_4(&rfc8448_session);
            test_rfc8448_5();
            test_rfc8448_6();
            test_rfc8448_7();

            // https://github.com/syncsynchalt/illustrated-tls13/captures/
            test_use_pre_master_secret();
        }

        load_certificate("rsa.crt", "rsa.key", nullptr);
        load_certificate("ecdsa.crt", "ecdsa.key", nullptr);

        {
            test_tls12_aead();
            test_pcap_tls13();
            test_pcap_tls12();
            test_construct_tls();
        }

        {
            test_pcap_dtls12();
            test_construct_dtls13();
            test_dtls_record_arrange();
            test_construct_dtls12_1();  // generate and arrange fragmented diagrams (record-handshake multiplicity 1..1)
            test_construct_dtls12_2();  // (record-handshake multiplicity 1..*)
        }

        {
            test_helloretryrequest();
            test_alert();

            test_pcap_tls13_http1();
        }
    } else {
        dump_clienthello();
    }

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);

    _cmdline->help();
    return _test_case.result();
}
