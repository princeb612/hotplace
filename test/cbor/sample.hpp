#ifndef __HOTPLACE_TEST_CBOR__
#define __HOTPLACE_TEST_CBOR__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    std::string content;

    OPTION() : CMDLINEOPTION() {
        // do nothing
    }
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_rfc7049_table4_1();
void test_rfc7049_table4_2();

void test_parse();

#endif
