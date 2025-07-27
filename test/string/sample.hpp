#ifndef __HOTPLACE_TEST_STRING__
#define __HOTPLACE_TEST_STRING__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_format();
void test_getline();
void test_gettoken();
void test_hexbin();
void test_constexpr_hide();
void test_constexpr_obf();
void test_obfuscate_string();
void test_printf();
void test_replace();
void test_scan();
void test_scan2();
void test_split();
void test_string();
void test_tokenize();

#endif
