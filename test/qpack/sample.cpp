/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9204 QPACK: Field Compression for HTTP/3
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void dump_qpack_session_routine(const char* stream, size_t size) { _logger->writeln(stream); }

void dump(const qpack_decode_t& item) {
    if (qpack_decode_capacity & item.flags) {
        _logger->writeln("> capacity %zi", item.capacity);
    } else if (qpack_decode_field_section_prefix & item.flags) {
        _logger->writeln("> field section prefix RIC=%zi Base=%zi", item.ric, item.base);
    } else if (qpack_decode_index & item.flags) {
        _logger->writeln("> Index   [%zi] %s: %s", item.index, item.name.c_str(), item.value.c_str());
    } else if (qpack_decode_nameref & item.flags) {
        _logger->writeln("> NameRef [%zi] %s: %s", item.index, item.name.c_str(), item.value.c_str());
    } else if (qpack_decode_namevalue & item.flags) {
        _logger->writeln("> NameVal %s: %s", item.name.c_str(), item.value.c_str());
    } else if (qpack_decode_ack & item.flags) {
        _logger->writeln("> ACK STREAM %zi", item.streamid);
    } else if (qpack_decode_cancel & item.flags) {
        _logger->writeln("> CANCEL STREAM %zi", item.streamid);
    } else if (qpack_decode_dup & item.flags) {
        _logger->writeln("> DUP [%zi] %s: %s", item.index, item.name.c_str(), item.value.c_str());
    } else if (qpack_decode_inc & item.flags) {
        _logger->writeln("> INC %zi", item.inc);
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
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
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
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    openssl_startup();

    test_rfc9204_b();
    test_zero_capacity();
    test_tiny_capacity();
    test_small_capacity();

    test_qpack_stream();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
