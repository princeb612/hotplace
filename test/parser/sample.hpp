#ifndef __HOTPLACE_TEST_PARSER__
#define __HOTPLACE_TEST_PARSER__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_dump_testdata();
void test_parser();
void test_parser_options();
void test_parser_search();
void test_parser_compare();
void test_multipattern_search();
void test_patterns();

#endif
