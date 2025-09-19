#ifndef __HOTPLACE_TEST_HPACK__
#define __HOTPLACE_TEST_HPACK__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
extern t_shared_instance<hpack_encoder> encoder;

void dump_hpack_session_routine(const char* stream, size_t size);

void test_huffman_codes();
void test_rfc7541_c_1();
void test_rfc7541_c_2();
void test_rfc7541_c_3();
void test_rfc7541_c_4();
void test_rfc7541_c_5();
void test_rfc7541_c_6();

void test_h2_header_frame();

#endif
