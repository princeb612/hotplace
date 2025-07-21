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
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

enum {
    mode_encnum = 1,
    mode_encode = 2,
    mode_decode = 3,
};

void whatsthis() {
    // encode/decode
    // -n 1073741823
    // > encode
    //   1073741823 (0x3fffffff) -> bfffffff
    //
    // -e 0x3fffffff
    // > encode
    //   0x3fffffff (1073741823) -> bfffffff
    //
    // -d '0xc00000004 0000000'
    // > decode
    //   c000000040000000 -> 0x40000000 (1073741824)
    const OPTION& option = _cmdline->value();
    basic_stream bs;
    binary_t bin_input;
    binary_t bin_encoded;
    switch (option.mode) {
        case mode_encnum: {
            auto i64_input = t_atoi<uint64>(option.content);
            quic_write_vle_int(i64_input, bin_encoded);
            auto encoded = std::move(base16_encode(bin_encoded));
            bs.printf("> encode\n");
            bs.printf("  %I64i (0x%I64x) -> %s\n", i64_input, i64_input, encoded.c_str());
        } break;
        case mode_encode: {
            bin_input = std::move(base16_decode_rfc(option.content));
            auto i64_input = t_binary_to_integer<uint64>(bin_input);
            quic_write_vle_int(i64_input, bin_encoded);
            auto encoded = std::move(base16_encode(bin_encoded));
            bs.printf("> encode\n");
            bs.printf("  0x%I64x (%I64i) -> %s\n", i64_input, i64_input, encoded.c_str());
        } break;
        case mode_decode: {
            bin_input = std::move(base16_decode_rfc(option.content));
            size_t pos = 0;
            uint64 i64_decoded = 0;
            quic_read_vle_int(&bin_input[0], bin_input.size(), pos, i64_decoded);

            bs.printf("> decode\n");
            bs.printf("  %s -> 0x%I64x (%I64i)\n", base16_encode(bin_input).c_str(), i64_decoded, i64_decoded);
        } break;
        default:
            break;
    }
    _logger->consoleln(bs);
}

std::string direction_string(tls_direction_t dir) {
    std::string s;
    s += "{";
    if (from_client == dir) {
        s += "client->server";
    } else {
        s += "client<-server";
    }
    s += "}";
    return s;
}

void test_rfc_9001_construct_initial(testvector_initial_packet* item, tls_session* session) {
    _logger->colorln("QUIC #construct initial");

    // use RFC 9001 test vector
    //   do not construct TLS handshakes and extensions

    binary_t bin_dcid;
    binary_t bin_scid;
    binary_t bin_token;
    binary_t bin_unprotected_header;
    binary_t bin_protected_header;
    binary_t bin_frame;
    binary_t bin_payload;
    binary_t bin_tag;
    binary_t bin_expect_unprotected_header;
    binary_t bin_expect_protected_header;
    binary_t bin_expect_result;

    const char* text = item->text;
    const char* func = item->func;
    tls_direction_t dir = item->dir;
    uint32 pn = item->pn;
    uint8 pn_length = item->pn_length;
    size_t length = item->length;

    size_t pos = 0;
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;

    // DCID, expectation data, result, ...
    {
        if (item->dcid) {
            bin_dcid = std::move(base16_decode_rfc(item->dcid));
        }
        if (item->scid) {
            bin_scid = std::move(base16_decode_rfc(item->scid));
        }
        if (item->token) {
            bin_token = std::move(base16_decode_rfc(item->token));
        }
        bin_frame = std::move(base16_decode_rfc(item->frame));
        if (item->pad) {
            bin_frame.resize(item->resize);
        }

        bin_expect_unprotected_header = std::move(base16_decode_rfc(item->expect_unprotected_header));
        bin_expect_protected_header = std::move(base16_decode_rfc(item->expect_protected_header));
        bin_expect_result = std::move(base16_decode_rfc(item->expect_result));
    }

    auto& protection = session->get_tls_protection();
    auto& secrets = protection.get_secrets();

    auto lambda_dump = [&](const char* text, const binary_t& bin) -> void { _logger->writeln("> %-21s : %s", text, base16_encode(bin).c_str()); };

    {
        lambda_dump("initial secret", secrets.get(tls_secret_initial_quic));
        lambda_dump("client initial secret", secrets.get(tls_secret_initial_quic_client));
        lambda_dump("client key", secrets.get(tls_secret_initial_quic_client_key));
        lambda_dump("client iv", secrets.get(tls_secret_initial_quic_client_iv));
        lambda_dump("client hp", secrets.get(tls_secret_initial_quic_client_hp));
        lambda_dump("server initial secret", secrets.get(tls_secret_initial_quic_server));
        lambda_dump("server key", secrets.get(tls_secret_initial_quic_server_key));
        lambda_dump("server iv", secrets.get(tls_secret_initial_quic_server_iv));
        lambda_dump("server hp", secrets.get(tls_secret_initial_quic_server_hp));
    }

    // write
    {
        quic_packet_initial initial(session);

        initial.set_dcid(bin_dcid).set_scid(bin_scid).set_payload(bin_frame);
        initial.set_token(bin_token);
        initial.set_pn(pn, pn_length);

        // unprotected header
        initial.write_header(bin_unprotected_header);

        {
            // [test vector] set record no
            session->set_recordno(dir, pn, protection_initial);

            // packet protection -> protected header, payload, tag
            initial.write(dir, bin_protected_header, bin_payload, bin_tag);

            // TLS forward secrecy applied...
            // do not call initial.write(dir, packet); after previous write member
        }

        {
            _test_case.assert(bin_payload.size(), func, "write");

            binary_t temp;
            binary_append(temp, bin_protected_header);
            binary_append(temp, bin_payload);
            binary_append(temp, bin_tag);
            _logger->hdump("> protected_header", bin_protected_header, 16, 3);
            _logger->hdump("> payload", bin_payload, 16, 3);
            _logger->hdump("> tag", bin_tag, 16, 3);
            _logger->hdump("> result", temp, 16, 3);
            _logger->hdump("> result (expected)", bin_expect_result, 16, 3);
            _test_case.assert(bin_frame == initial.get_payload(), func, "%s #payload", text);
            _test_case.assert(bin_expect_result == temp, func, "%s #result", text);

            _logger->hdump("> unprotected header (AAD)", bin_unprotected_header, 16, 3);
            _logger->writeln("   %s", base16_encode(bin_unprotected_header).c_str());
            _logger->hdump("> expected unprotected header (AAD)", bin_expect_unprotected_header, 16, 3);
            _logger->writeln("   %s", base16_encode(bin_expect_unprotected_header).c_str());
            _logger->hdump("> protected header", bin_protected_header, 16, 3);
            _logger->writeln("   %s", base16_encode(bin_protected_header).c_str());
            _logger->hdump("> expected protected header", bin_expect_protected_header, 16, 3);
            _logger->writeln("   %s", base16_encode(bin_expect_protected_header).c_str());

            _test_case.assert(quic_packet_type_initial == initial.get_type(), func, "%s #initial packet", text);
            _test_case.assert(bin_dcid == initial.get_dcid(), func, "%s #DCID", text);
            _test_case.assert(bin_scid == initial.get_scid(), func, "%s #SCID", text);
            _test_case.assert(length == initial.get_length(), func, "%s #length %zi", text, length);
            _test_case.assert(pn == initial.get_pn(), func, "%s #packet number %i", text, pn);
            _test_case.assert(pn_length == initial.get_pn_length(), func, "%s #packet number length %i", text, pn_length);
            _test_case.assert(bin_expect_unprotected_header == bin_unprotected_header, func, "%s #unprotected header", text);
            _test_case.assert(bin_expect_protected_header == bin_protected_header, func, "%s #protected header", text);
        }
    }
}

void test_rfc_9001_send_initial(testvector_initial_packet* item, tls_session* session) {
    _logger->colorln("QUIC #send initial");

    return_t ret = errorcode_t::success;
    binary_t bin_dcid;
    binary_t bin_scid;
    binary_t bin_expect_result;

    const char* text = item->text;
    const char* func = item->func;
    tls_direction_t dir = item->dir;
    uint32 pn = item->pn;
    uint8 pn_length = item->pn_length;
    size_t length = item->length;

    size_t pos = 0;
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;

    // DCID, expectation data, result, ...
    {
        // bin_odcid = base16_decode_rfc(item->odcid);
        if (item->dcid) {
            bin_dcid = std::move(base16_decode_rfc(item->dcid));
        }
        if (item->scid) {
            bin_scid = std::move(base16_decode_rfc(item->scid));
        }

        bin_expect_result = std::move(base16_decode_rfc(item->expect_result));
    }

    // read
    {
        quic_packet_initial initial(session);

        pos = 0;
        ret = initial.read(dir, &bin_expect_result[0], bin_expect_result.size(), pos);

        _test_case.test(ret, func, "%s #read", text);
        _test_case.assert(quic_packet_type_initial == initial.get_type(), func, "%s #initial packet", text);
        _test_case.assert(bin_dcid == initial.get_dcid(), func, "%s #DCID", text);
        _test_case.assert(bin_scid == initial.get_scid(), func, "%s #SCID", text);
        _test_case.assert(pn == initial.get_pn(), func, "%s #packet number %i", text, initial.get_pn());
        _test_case.assert(pn_length == initial.get_pn_length(), func, "%s #packet number length %i", text, initial.get_pn_length());
        _test_case.assert(length == initial.get_length(), func, "%s #length %zi %I64u", text, length, initial.get_length());
    }
}

void test_rfc_9001_retry(testvector_retry_packet* item, tls_session* session) {
    // binary_t bin_odcid;
    binary_t bin_dcid;
    binary_t bin_scid;
    binary_t bin_token;
    binary_t bin_result;
    binary_t bin_expect_header;
    binary_t bin_expect_result;
    binary_t bin_expect_tag;

    const char* text = item->text;
    const char* func = item->func;
    tls_direction_t dir = item->dir;

    {
        if (item->dcid) {
            bin_dcid = std::move(base16_decode_rfc(item->dcid));
        }
        if (item->scid) {
            bin_scid = std::move(base16_decode_rfc(item->scid));
        }
        if (item->token) {
            bin_token = std::move(base16_decode_rfc(item->token));
        }
        bin_expect_result = std::move(base16_decode_rfc(item->expect_result));
        bin_expect_tag = std::move(base16_decode_rfc(item->expect_tag));
    }

    // write
    {
        quic_packet_retry retry(session);
        retry.set_dcid(bin_dcid).set_scid(bin_scid);
        retry.set_retry_token(bin_token);
        retry.write(dir, bin_result);
        _test_case.assert(bin_result == bin_expect_result, func, "RFC 9001 A.4.  Retry #write");
    }

    // read
    {
        size_t pos = 0;
        quic_packet_retry retry(session);
        retry.read(dir, &bin_result[0], bin_result.size(), pos);

        _test_case.assert(bin_dcid == retry.get_dcid(), func, "RFC 9001 A.4.  Retry #dcid");
        _test_case.assert(bin_scid == retry.get_scid(), func, "RFC 9001 A.4.  Retry #scid");
        _test_case.assert(bin_token == retry.get_retry_token(), func, "RFC 9001 A.4.  Retry #retry token");
        _test_case.assert(bin_expect_tag == retry.get_integrity_tag(), func, "RFC 9001 A.4.  Retry #retry integrity tag");
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.trace_level = atoi(param); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.trace_level = 0; }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.trace_level = 2; }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-k", "keylog", [](OPTION& o, char* param) -> void { o.keylog = 1; }).optional()
                << t_cmdarg_t<OPTION>("-n", "encode number", [](OPTION& o, char* param) -> void { o.set(mode_encnum, param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-e", "encode base16", [](OPTION& o, char* param) -> void { o.set(mode_encode, param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-b", "decode base16", [](OPTION& o, char* param) -> void { o.set(mode_decode, param); }).optional().preced()
                << t_cmdarg_t<OPTION>("--q", "test quic.xargs.org", [](OPTION& o, char* param) -> void { o.flags |= test_flag_quic; }).optional()
                << t_cmdarg_t<OPTION>("--pcap", "test pcap", [](OPTION& o, char* param) -> void { o.flags |= test_flag_pcap; }).optional();
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
    if (option.keylog) {
        auto lambda = [&](const char* line) -> void { _logger->writeln(line); };
        auto sslkeylog = sslkeylog_exporter::get_instance();
        sslkeylog->set(lambda);
    }

    _logger->setcolor(bold, magenta);

    openssl_startup();

    if ((test_flag_quic & option.flags) || (0 == option.flags)) {
        test_quic_xargs_org();
    }

    if (0 == option.flags) {
        // RFC 9000
        test_rfc_9000_a1();
        test_rfc_9000_a2();
        test_rfc_9000_a3();

        // RFC 9001
        test_rfc_9001_section4();
        test_rfc_9001_a1();
        test_rfc_9001_a2();
        test_rfc_9001_a3();
        test_rfc_9001_a4();
        test_rfc_9001_a5();

        // RFC 9369
        test_rfc_9369_a1();
        test_rfc_9369_a2();
        test_rfc_9369_a3();
        test_rfc_9369_a4();
        test_rfc_9369_a5();
    }

    if ((test_flag_pcap & option.flags) || (0 == option.flags)) {
        // http3.pcapng
        test_pcap_quic();
    }

    if (0 == option.flags) {
        test_quic_frame();
        test_construct_quic();
    }

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    whatsthis();
    return _test_case.result();
}
