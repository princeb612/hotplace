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
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

return_t _cmdret = errorcode_t::success;

void whatsthis() {
    return_t ret = errorcode_t::success;

    // $ ./test-encode -b64u AQIDBAU
    //  what u want to know
    //  < AQIDBAU
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64
    //    AQIDBAU=

    // $ ./test-encode -b64 AQIDBAU=
    //  what u want to know
    //  < AQIDBAU=
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64u
    //    AQIDBAU

    //  $ ./test-encode -rfc "[1,2 , 3, 4, 5]"
    //  what u want to know
    //  < [1,2 , 3, 4, 5]
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64
    //    AQIDBAU=
    //  > b64url
    //    AQIDBAU

    //  ./test-encode -rfc "01:02 : 03:04:05"
    //  what u want to know
    //  < 01:02 : 03:04:05
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64
    //    AQIDBAU=
    //  > b64url
    //    AQIDBAU

    //
    //  $ echo AQIDBAU= | base64 -d | xxd
    //  00000000: 0102 0304 05                             .....

    const OPTION o = _cmdline->value();
    if (o.mode && errorcode_t::success == _cmdret) {
        basic_stream bs;
        basic_stream additional;
        binary_t what;
        binary_t temp;
        std::string stemp;
        switch (o.mode) {
            case decode_b64u:
                what = base64_decode(o.content, base64_encoding_t::base64url_encoding);
                additional << "> b16\n  " << base16_encode(what).c_str() << "\n";
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                break;
            case decode_b64:
                what = base64_decode(o.content, base64_encoding_t::base64_encoding);
                additional << "> b16\n  " << base16_encode(what).c_str() << "\n";
                additional << "> b64u\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case encode_plaintext:
                what = str2bin(o.content);
                base16_encode(o.content, temp);
                additional << "> b16\n  " << bin2str(temp).c_str() << "\n";
                additional << "> b64\n  " << base64_encode(o.content).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(o.content, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case decode_b16:
                what = base16_decode(o.content);
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case encode_b16_rfc:
                stemp = base16_encode_rfc(o.content);
                what = base16_decode(stemp);
                additional << "> b16\n  " << stemp.c_str() << "\n";
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
        }

        if (encode_plaintext == o.mode) {
            dump_memory(str2bin(o.content), &bs, 16, 2);
        } else {
            dump_memory(what, &bs, 16, 2);
        }

        if (o.filename.size() && o.content.size()) {
            std::ofstream file(o.filename.c_str(), std::ios::trunc);
            file.write((const char*)&what[0], what.size());
            file.close();
        }

        basic_stream dbs;
        dbs << "what u want to know"
            << "\n"
            << "< " << o.content << "\n"
            << bs;
        _logger->consoleln(dbs);

        if (additional.size()) {
            _logger->consoleln(additional);
        }
    } else {
        _cmdline->help();
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);

    constexpr char constexpr_helpmsg_rfc[] = R"(encode base16 from rfc style expression ex. "[1,2,3,4,5]" or "01:02:03:04:05" or "01 02 03 04 05")";

    (*_cmdline) << t_cmdarg_t<OPTION>("-b64u", "decode base64url", [](OPTION& o, char* param) -> void { o.set(decode_b64u, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-b64", "decode base64", [](OPTION& o, char* param) -> void { o.set(decode_b64, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-b16", "decode base16", [](OPTION& o, char* param) -> void { o.set(decode_b16, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-t", "plaintext", [](OPTION& o, char* param) -> void { o.set(encode_plaintext, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-rfc", constexpr_helpmsg_rfc, [](OPTION& o, char* param) -> void { o.set(encode_b16_rfc, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-out", "write to file", [](OPTION& o, char* param) -> void { o.setfile(param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();

    _cmdret = _cmdline->parse(argc, argv);

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
            std::string ct;
            std::string ev;
            auto advisor = trace_advisor::get_instance();
            advisor->get_names(category, event, ct, ev);
            _logger->write("[%s][%s]\n%.*s", ct.c_str(), ev.c_str(), (unsigned)s->size(), s->data());
        };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    _test_case.begin("b16 encoding");
    test_base16();
    test_base16_func();
    test_base16_decode();
    test_base16_oddsize();
    test_base16_rfc();

    _test_case.begin("b64 encoding");
    test_base64();

    _logger->flush();

    _test_case.report(5);
    whatsthis();
    return _test_case.result();
}
