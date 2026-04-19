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

void do_test_dump_routine(const byte_t* dump_address, size_t dump_size, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0) {
    return_t ret = errorcode_t::success;
    _logger->dump(dump_address, dump_size, hex_part, indent);
    _test_case.test(ret, __FUNCTION__, "dump addr %p size %zi hex %i indent %i rebase %zi", dump_address, dump_size, hex_part, indent, rebase);
}

void test_dumpmemory() {
    _test_case.begin("dump_memory");
    return_t ret = errorcode_t::success;
    ansi_string bs;
    const char* text = "still a man hears what he wants to hear and disregards the rest";  // the boxer - Simon & Garfunkel

    do_test_dump_routine((byte_t*)text, strlen(text));
    do_test_dump_routine((byte_t*)text, strlen(text), 32);
    do_test_dump_routine((byte_t*)text, strlen(text), 16, 4);
    do_test_dump_routine((byte_t*)text, strlen(text), 16, 4, 0x1000);

    std::string str(text);
    _logger->hdump("dump", str, 16, 3);
    _test_case.assert(true, __FUNCTION__, "string");

    binary_t bin = std::move(str2bin(str));
    _logger->hdump("dump", bin, 16, 3);
    _test_case.assert(true, __FUNCTION__, "binary_t");

    binary_t bin2;
    _logger->hdump("dump", bin2, 16, 3);
    _test_case.assert(true, __FUNCTION__, "dump blank");
}

void testcase_dumpmemory() { test_dumpmemory(); }
