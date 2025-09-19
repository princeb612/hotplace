#ifndef __HOTPLACE_TEST_CMDLINE__
#define __HOTPLACE_TEST_CMDLINE__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    std::string infile;
    std::string outfile;
    bool keygen;

    OPTION() : CMDLINEOPTION(), keygen(false) {};
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test1();

#endif
