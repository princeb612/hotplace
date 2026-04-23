/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_parse.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include "sample.hpp"

void do_test_parse_routine(const char* text, const char* input, const char* diagnostic) {
    return_t ret = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* handle = nullptr;
    ansi_string bs;
    binary_t bin;
    bool test = false;
    bool test2 = false;

    reader.open(&handle);
    ret = reader.parse(handle, input);  // read
    if (errorcode_t::success == ret) {
        reader.publish(handle, &bs);   // diagnostic
        reader.publish(handle, &bin);  // concise
        reader.close(handle);

        {
            test_case_notimecheck notimecheck(_test_case);

            std::string b16;
            base16_encode(bin, b16);
            _logger->writeln("diagnostic %s", bs.c_str());
            _logger->writeln("cbor       %s", b16.c_str());

            test = (0 == stricmp(input, b16.c_str()));
            test2 = (bs == diagnostic);
        }
    }

    _test_case.assert(test, __FUNCTION__, text);
}

void testcase_parse() {
    _test_case.begin("test3.parse");
    for (auto i = 0; i < sizeof_test_vector_parse; ++i) {
        const auto& item = _test_vector_parse[i];
        do_test_parse_routine(item.text, item.cbor, item.diag);
    }
}
