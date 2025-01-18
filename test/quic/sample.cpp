/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 *            QUIC integrates the TLS handshake [TLS13], although using a customized framing for protecting packets.
 *
 *          RFC 2246 The TLS Protocol Version 1.0
 *           7.4. Handshake protocol
 *           7.4.1. Hello messages
 *           7.4.1.1. Hello request
 *           7.4.1.2. Client hello
 *
 *          RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1
 *           7.4. Handshake Protocol
 *           7.4.1. Hello Messages
 *           7.4.1.2. Client Hello
 *
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *           7.4.  Handshake Protocol
 *           7.4.1.  Hello Messages
 *           7.4.1.2.  Client Hello
 *
 *           4.1.2.  Client Hello
 *             Structure of this message:
 *
 *                uint16 ProtocolVersion;
 *                opaque Random[32];
 *
 *                uint8 CipherSuite[2];    // Cryptographic suite selector
 *
 *                struct {
 *                    ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *                    Random random;
 *                    opaque legacy_session_id<0..32>;
 *                    CipherSuite cipher_suites<2..2^16-2>;
 *                    opaque legacy_compression_methods<1..2^8-1>;
 *                    Extension extensions<8..2^16-1>;
 *                } ClientHello;
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
            auto encoded = base16_encode(bin_encoded);
            bs.printf("> encode\n");
            bs.printf("  %I64i (0x%I64x) -> %s\n", i64_input, i64_input, encoded.c_str());
        } break;
        case mode_encode: {
            bin_input = base16_decode_rfc(option.content);
            auto i64_input = t_binary_to_integer<uint64>(bin_input);
            quic_write_vle_int(i64_input, bin_encoded);
            auto encoded = base16_encode(bin_encoded);
            bs.printf("> encode\n");
            bs.printf("  0x%I64x (%I64i) -> %s\n", i64_input, i64_input, encoded.c_str());
        } break;
        case mode_decode: {
            bin_input = base16_decode_rfc(option.content);
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

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-n", "encode number", [](OPTION& o, char* param) -> void { o.set(mode_encnum, param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-e", "encode base16", [](OPTION& o, char* param) -> void { o.set(mode_encode, param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-d", "decode base16", [](OPTION& o, char* param) -> void { o.set(mode_decode, param); }).optional().preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
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

    openssl_startup();

    // RFC 9000 Appendix A.  Pseudocode

    test_rfc_9000_a1();
    test_rfc_9000_a2();
    test_rfc_9000_a3();

    test_rfc_9001_section4();

    // RFC 9001 5.  Packet Protection
    // RFC 9001 Appendix A.  Sample Packet Protection

    test_rfc_9001_a1();
    test_rfc_9001_a2();
    test_rfc_9001_a3();
    test_rfc_9001_a4();
    test_rfc_9001_a5();

    test_quic_xargs_org();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    whatsthis();
    return _test_case.result();
}
