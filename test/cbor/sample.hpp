/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_CBOR__
#define __HOTPLACE_TEST_CBOR__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    std::string content;

    OPTION() : CMDLINEOPTION() {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

struct test_vector_parse {
    const char* text;
    const char* cbor;
    const char* diag;
};
extern const struct test_vector_parse _test_vector_parse[];
extern const size_t sizeof_test_vector_parse;

void testcase_rfc7049();
void testcase_parse();

#endif
