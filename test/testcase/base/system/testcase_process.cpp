/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_process.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_process_noredirection() {
    _test_case.begin("process");
    execparam param;
#if defined __GNUC__
    param.executable = "ls";
    param.arguments = {"-w", "1"};
#elif defined _MSC_VER
    param.executable = "cmd.exe";
    param.arguments = {"/c", "dir", "-b"};
#endif

    process p;
    bool spawned = p.spawn(param);
    _test_case.assert(spawned, __FUNCTION__, "spawn");

    if (spawned) {
        int exitcode = p.wait();
        _test_case.assert(0 == exitcode, __FUNCTION__, "exit code");
    }
}

void test_process_redirection() {
    _test_case.begin("process");

    execparam param;
#if defined __GNUC__
    param.executable = "ls";
    param.arguments = {"-w", "1"};
#elif defined _MSC_VER
    param.executable = "cmd.exe";
    param.arguments = {"/c", "dir", "-b"};
#endif
    // enable I/O redirection
    param.io_redirection = true;

    process p;
    bool spawned = p.spawn(param);
    _test_case.assert(spawned, __FUNCTION__, "spawn");

    if (spawned) {
        auto redir = p.get_redirection();

        if (redir) {
            std::string output;
            char buffer[128];
            size_t bytes_read = 0;

            while ((bytes_read = redir->read_stdout(buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytes_read] = '\0';
                output += buffer;
            }

            _logger->writeln(output);  // run using the -d parameter to display

            _test_case.assert(false == output.empty(), __FUNCTION__, "check redirection");
        }

        int exitcode = p.wait();
        _test_case.assert(0 == exitcode, __FUNCTION__, "exit code");
    }
}

void testcase_process() {
    test_process_noredirection();
    test_process_redirection();
}
