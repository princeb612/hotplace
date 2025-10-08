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

void test_exception() {
    _test_case.begin("exception");
    return_t rc = errorcode_t::success;
    std::string reason;
    __try {
        throw exception(not_specified);
    } catch (exception e) {
        rc = e.get_errorcode();
        reason = e.get_error_message();
        _logger->writeln("caught exception 0x%08x %s", rc, reason.c_str());
    }
    _test_case.assert(not_specified == rc, __FUNCTION__, "exception %s", reason.c_str());
}
