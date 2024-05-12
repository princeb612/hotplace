/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

typedef struct _CMDOPTION {
    std::string infile;
    std::string outfile;
    bool keygen;

    _CMDOPTION() : keygen(false){};
    void reset() {
        keygen = false;
        infile.clear();
        outfile.clear();
    }
} CMDOPTION;

void test_cmdline(cmdline_t<CMDOPTION>& cmdline, bool expect, int argc, char** argv) {
    return_t ret = errorcode_t::success;
    CMDOPTION& suboption = cmdline.value();

    suboption.reset();

    std::string args;
    for (int i = 0; i < argc; i++) {
        args += argv[i];
        if (i + 1 < argc) {
            args += " ";
        }
    }
    _logger->writeln("condition argc %i argv '%s'", argc, args.c_str());

    ret = cmdline.parse(argc, argv);
    if (errorcode_t::success != ret) {
        cmdline.help();
    }

    // CMDOPTION suboption = cmdline.value ();
    basic_stream bs;
    bs << "infile " << suboption.infile << "\n"
       << "outfile " << suboption.outfile << "\n"
       << "keygen " << suboption.keygen;
    _logger->writeln(bs);

    bool test = (errorcode_t::success == ret);
    _test_case.assert(expect ? test : !test, __FUNCTION__, "cmdline %s (%s)", args.c_str(), expect ? "positive test" : "negative test");
}

void test1() {
    _test_case.begin("commandline");

    CMDOPTION option;

    cmdline_t<CMDOPTION> cmdline;

    cmdline << cmdarg_t<CMDOPTION>("-in", "input", [&](CMDOPTION& o, char* param) -> void { o.infile = param; }).preced()
            << cmdarg_t<CMDOPTION>("-out", "output", [&](CMDOPTION& o, char* param) -> void { o.outfile = param; }).preced()
            << cmdarg_t<CMDOPTION>("-keygen", "keygen", [&](CMDOPTION& o, char* param) -> void { o.keygen = true; }).optional();

    int argc = 0;
    argc = 0;
    char* argv[5] = {
        nullptr,
    };

    _test_case.begin("case - invalid parameter");

    argc = 2;
    argv[0] = (char*)"-in";
    argv[1] = (char*)"test.in";
    test_cmdline(cmdline, false, argc, argv);  // wo -out

    argc = 3;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"-in";
    argv[2] = (char*)"test.in";
    test_cmdline(cmdline, false, argc, argv);  // wo -out

    argc = 3;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-in";
    test_cmdline(cmdline, false, argc, argv);  // wo -in and -out

    argc = 4;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-in";
    argv[3] = (char*)"test.out";
    test_cmdline(cmdline, false, argc, argv);  // wo -out

    argc = 4;
    argv[0] = (char*)"-in-";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-out";
    argv[3] = (char*)"test.out";
    test_cmdline(cmdline, false, argc, argv);  // wo -in

    // wo -in (expect value not token)
    argc = 5;
    argv[0] = (char*)"-in";
    argv[1] = (char*)"-keygen";
    argv[2] = (char*)"test.in";
    argv[3] = (char*)"-out";
    argv[4] = (char*)"test.out";
    test_cmdline(cmdline, false, argc, argv);

    _test_case.begin("case - valid parameter");

    argc = 4;
    argv[0] = (char*)"-in";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-out";
    argv[3] = (char*)"test.out";
    test_cmdline(cmdline, true, argc, argv);  // -token.preced value

    argc = 5;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"-in";
    argv[2] = (char*)"test.in";
    argv[3] = (char*)"-out";
    argv[4] = (char*)"test.out";
    test_cmdline(cmdline, true, argc, argv);  // -token.preced value -token.optional
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    test1();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
