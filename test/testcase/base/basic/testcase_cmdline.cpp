/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_cmdline.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

struct MYOPTION : public CMDLINEOPTION {
    std::string infile;
    std::string outfile;
    bool keygen;

    MYOPTION() : CMDLINEOPTION(), keygen(false) {};
};

void do_test_cmdline(bool expect, int argc, const char** argv) {
    return_t ret = errorcode_t::success;

    t_cmdline_t<MYOPTION> cmdline;

    cmdline << t_cmdarg_t<MYOPTION>("-v", "verbose", [](MYOPTION& o, const char* param) -> void { o.verbose = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-l", "log file", [](MYOPTION& o, const char* param) -> void { o.log = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-t", "log time", [](MYOPTION& o, const char* param) -> void { o.time = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-in", "input", [&](MYOPTION& o, const char* param) -> void { o.infile = param; }).preced()
            << t_cmdarg_t<MYOPTION>("-out", "output", [&](MYOPTION& o, const char* param) -> void { o.outfile = param; }).preced()
            << t_cmdarg_t<MYOPTION>("-keygen", "keygen", [&](MYOPTION& o, const char* param) -> void { o.keygen = true; }).optional();

    std::string args;
    for (int i = 1; i < argc; i++) {
        args += argv[i];
        if (i + 1 < argc) {
            args += " ";
        }
    }
    _logger->writeln("condition argc %i argv '%s'", argc, args.c_str());

    ret = cmdline.parse(argc, (char**)argv);
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

void test_cmdline() {
    _test_case.begin("commandline");

    int argc = 0;
    const char* argv[10] = {};
    argv[0] = "test";

    argc = 3;
    argv[1] = "-in";
    argv[2] = "test.in";
    do_test_cmdline(false, argc, argv);  // missing -out

    argc = 6;
    argv[1] = "-keygen";
    argv[2] = "-in";
    argv[3] = "test.in";
    argv[4] = "-out";
    argv[5] = "test.out";
    do_test_cmdline(true, argc, argv);  // -token.preced value -token.optional
}

void testcase_cmdline() { test_cmdline(); }
