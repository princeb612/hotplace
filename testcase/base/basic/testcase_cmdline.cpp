/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

struct MYOPTION : public CMDLINEOPTION {
    std::string infile;
    std::string outfile;
    bool keygen;

    MYOPTION() : CMDLINEOPTION(), keygen(false) {};
};

void do_test_cmdline(bool expect, int argc, char** argv) {
    return_t ret = errorcode_t::success;

    t_cmdline_t<MYOPTION> cmdline;

    cmdline << t_cmdarg_t<MYOPTION>("-v", "verbose", [](MYOPTION& o, char* param) -> void { o.verbose = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-l", "log file", [](MYOPTION& o, char* param) -> void { o.log = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-t", "log time", [](MYOPTION& o, char* param) -> void { o.time = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-in", "input", [&](MYOPTION& o, char* param) -> void { o.infile = param; }).preced()
            << t_cmdarg_t<MYOPTION>("-out", "output", [&](MYOPTION& o, char* param) -> void { o.outfile = param; }).preced()
            << t_cmdarg_t<MYOPTION>("-keygen", "keygen", [&](MYOPTION& o, char* param) -> void { o.keygen = true; }).optional();

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

    const MYOPTION& cmdoption = cmdline.value();

    // MYOPTION cmdoption = cmdline.value ();
    _logger->writeln([&](basic_stream& bs) -> void {
        bs << "infile " << cmdoption.infile << "\n"
           << "outfile " << cmdoption.outfile << "\n"
           << "keygen " << cmdoption.keygen;
    });

    bool test = (errorcode_t::success == ret);
    _test_case.assert(expect ? test : !test, __FUNCTION__, "cmdline %s (%s)", args.c_str(), expect ? "positive test" : "negative test");
}

void test_cmdline_invalid_parameter() {
    _test_case.begin("commandline");

    int argc = 0;
    argc = 0;
    char* argv[5] = {
        nullptr,
    };

    argc = 2;
    argv[0] = (char*)"-in";
    argv[1] = (char*)"test.in";
    do_test_cmdline(false, argc, argv);  // wo -out

    argc = 3;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"-in";
    argv[2] = (char*)"test.in";
    do_test_cmdline(false, argc, argv);  // wo -out

    argc = 3;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-in";
    do_test_cmdline(false, argc, argv);  // wo -in and -out

    argc = 4;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-in";
    argv[3] = (char*)"test.out";
    do_test_cmdline(false, argc, argv);  // wo -out

    argc = 4;
    argv[0] = (char*)"-in-";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-out";
    argv[3] = (char*)"test.out";
    do_test_cmdline(false, argc, argv);  // wo -in

    // wo -in (expect value not token)
    argc = 5;
    argv[0] = (char*)"-in";
    argv[1] = (char*)"-keygen";
    argv[2] = (char*)"test.in";
    argv[3] = (char*)"-out";
    argv[4] = (char*)"test.out";
    do_test_cmdline(false, argc, argv);
}

void test_cmdline_valid_parameter() {
    _test_case.begin("commandline");

    int argc = 0;
    argc = 0;
    char* argv[5] = {
        nullptr,
    };

    argc = 4;
    argv[0] = (char*)"-in";
    argv[1] = (char*)"test.in";
    argv[2] = (char*)"-out";
    argv[3] = (char*)"test.out";
    do_test_cmdline(true, argc, argv);  // -token.preced value

    argc = 5;
    argv[0] = (char*)"-keygen";
    argv[1] = (char*)"-in";
    argv[2] = (char*)"test.in";
    argv[3] = (char*)"-out";
    argv[4] = (char*)"test.out";
    do_test_cmdline(true, argc, argv);  // -token.preced value -token.optional
}

void testcase_cmdline() {
    test_cmdline_invalid_parameter();
    test_cmdline_valid_parameter();
}
