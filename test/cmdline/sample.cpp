/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

typedef struct _OPTION {
    std::string infile;
    std::string outfile;
    bool keygen;

    _OPTION () : keygen (false)
    {
    };
} OPTION;

void test1 (int argc, char** argv)
{
    return_t ret = errorcode_t::success;
    cmdline_t<OPTION> cmdline;

    cmdline
        << cmdarg_t<OPTION> ("-in", "input", [&](OPTION& o, char* param) -> void {
        o.infile = param;
    }).preced ()
        << cmdarg_t<OPTION> ("-out", "output", [&](OPTION& o, char* param) -> void {
        o.outfile = param;
    }).preced ()
        << cmdarg_t<OPTION> ("-keygen", "keygen", [&](OPTION& o, char* param) -> void {
        o.keygen = true;
    }).optional ();
    ret = cmdline.parse (argc, argv);
    if (errorcode_t::success != ret) {
        cmdline.help ();
    }

    OPTION opt = cmdline.value ();
    std::cout << "infile "  << opt.infile.c_str () << std::endl;
    std::cout << "outfile " << opt.outfile.c_str () << std::endl;
    std::cout << "keygen "  << opt.keygen << std::endl;
}

void test_cmdline (cmdline_t<OPTION>& cmdline, bool expect, int argc, char** argv)
{
    return_t ret = errorcode_t::success;

    std::string args;
    for (int i = 0; i < argc; i++) {
        args += argv[i];
        if (i + 1 < argc) {
            args += " ";
        }
    }
    printf ("condition argc %i argv '%s'\n", argc, args.c_str ());

    ret = cmdline.parse (argc, argv);
    if (errorcode_t::success != ret) {
        cmdline.help ();
    }

    OPTION opt = cmdline.value ();
    std::cout << "infile "  << opt.infile.c_str () << std::endl;
    std::cout << "outfile " << opt.outfile.c_str () << std::endl;
    std::cout << "keygen "  << opt.keygen << std::endl;

    bool test = (errorcode_t::success == ret);
    _test_case.assert (expect ? test : !test, __FUNCTION__, "cmdline %s", args.c_str ());
}

void test2 ()
{
    _test_case.begin ("commandline");

    OPTION option;

    cmdline_t<OPTION> cmdline;

    cmdline
        << cmdarg_t<OPTION> ("-in", "input", [&](OPTION& o, char* param) -> void {
        o.infile = param;
    }).preced ()
        << cmdarg_t<OPTION> ("-out", "output", [&](OPTION& o, char* param) -> void {
        o.outfile = param;
    }).preced ()
        << cmdarg_t<OPTION> ("-keygen", "keygen", [&](OPTION& o, char* param) -> void {
        o.keygen = true;
    }).optional ();

    int argc = 0;
    argc = 0;
    char* argv[5] = { NULL, };

    _test_case.begin ("case - invalid parameter");

    argc = 2;
    argv[0] = (char*) "-in";
    argv[1] = (char*) "test.in";
    test_cmdline (cmdline, false, argc, argv); // wo -out

    argc = 3;
    argv[0] = (char*) "-keygen";
    argv[1] = (char*) "-in";
    argv[2] = (char*) "test.in";
    test_cmdline (cmdline, false, argc, argv); // wo -out

    argc = 3;
    argv[0] = (char*) "-keygen";
    argv[1] = (char*) "test.in";
    argv[2] = (char*) "-in";
    test_cmdline (cmdline, false, argc, argv); // wo -in and -out

    argc = 4;
    argv[0] = (char*) "-keygen";
    argv[1] = (char*) "test.in";
    argv[2] = (char*) "-in";
    argv[3] = (char*) "test.out";
    test_cmdline (cmdline, false, argc, argv); // wo -out

    argc = 4;
    argv[0] = (char*) "-in-";
    argv[1] = (char*) "test.in";
    argv[2] = (char*) "-out";
    argv[3] = (char*) "test.out";
    test_cmdline (cmdline, false, argc, argv); // wo -in

    // wo -in (expect value not token)
    argc = 5;
    argv[0] = (char*) "-in";
    argv[1] = (char*) "-keygen";
    argv[2] = (char*) "test.in";
    argv[3] = (char*) "-out";
    argv[4] = (char*) "test.out";
    test_cmdline (cmdline, false, argc, argv);

    _test_case.begin ("case - valid parameter");

    argc = 4;
    argv[0] = (char*) "-in";
    argv[1] = (char*) "test.in";
    argv[2] = (char*) "-out";
    argv[3] = (char*) "test.out";
    test_cmdline (cmdline, true, argc, argv); // -token.preced value

    argc = 5;
    argv[0] = (char*) "-keygen";
    argv[1] = (char*) "-in";
    argv[2] = (char*) "test.in";
    argv[3] = (char*) "-out";
    argv[4] = (char*) "test.out";
    test_cmdline (cmdline, true, argc, argv); // -token.preced value -token.optional
}

int main (int argc, char** argv)
{
    return_t ret = errorcode_t::success;

    test1 (argc, argv);
    test2 ();

    _test_case.report (5);
    return _test_case.result ();
}
