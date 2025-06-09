/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  mingw
 *      ./test-authenticate /c/windows/explorer.exe
 *  linux
 *      copy explorer.exe using scp
 *      ./test-authenticate explorer.exe
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int debug;
    int log;
    int time;
    std::string infile;

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

return_t test1() {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    authenticode_verifier verifier;
    authenticode_context_t* handle = nullptr;
    uint32 result = 0;

    __try2 {
        _test_case.begin("authenticode verification test - file");
        verifier.open(&handle);
        int opt = 0;
        verifier.set(handle, authenticode_ctrl_t::set_crl, &opt, sizeof(opt));
        verifier.add_trusted_rootcert(handle, "trust.crt", nullptr);
        ret = verifier.verify(handle, option.infile.c_str(), authenticode_flag_t::flag_separated, result);
        _logger->writeln("file verification : %08x", ret);
    }
    __finally2 {
        verifier.close(handle);
        _test_case.test(ret, __FUNCTION__, "trust file");
    }
    return ret;
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    return_t ret = errorcode_t::success;

    openssl_startup();

    __try2 {
        _cmdline.make_share(new t_cmdline_t<OPTION>);
        (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                    << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                    << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                    << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                    << t_cmdarg_t<OPTION>("-i", "file", [](OPTION& o, char* param) -> void { o.infile = param; }).preced().optional();
        ret = _cmdline->parse(argc, argv);
        if (errorcode_t::success != ret) {
            _cmdline->help();
            __leave2;
        }

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

        if (option.infile.empty()) {
            __leave2;
        }

        if (option.debug) {
            auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
            set_trace_debug(lambda_tracedebug);
            set_trace_option(trace_bt | trace_except | trace_debug);
        }

        // 1 linux style file path name
        //   a. mingw
        //     $ ./test-authenticate -v -i /c/home/tools/tool.exe
        //   b. linux
        //     $ ./test-authenticate -v -i ~/tools/tool.exe
        // 2 windows style file path name
        //   a. mingw-gdb
        //     $ gdb ./test-authenticate
        //     (gdb) r -v -i c:\home\tools\tool.exe
        //   b. windows
        //     dir> test-authenticate -v -i c:\home\tools\tool.exe

        test1();
    }
    __finally2 {
        // do nothing
    }

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
