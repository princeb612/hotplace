#ifndef __HOTPLACE_TEST_STREAM__
#define __HOTPLACE_TEST_STREAM__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_consolecolor();
void test_dumpmemory();
void test_i128();
void test_sprintf();
void test_vprintf();
void test_stream();
void test_stream_getline();
void test_stream_stdmap();
void test_vtprintf();
void test_autoindent();
void test_split();
void test_split2();
void test_split3();

#endif
