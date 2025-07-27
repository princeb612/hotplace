#ifndef __HOTPLACE_TEST_PAYLOAD__
#define __HOTPLACE_TEST_PAYLOAD__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_payload_write();
void test_payload_read();
void test_uint24();
void test_group();
void test_payload_uint24();
void test_http2_frame();
void test_quic_integer();
void test_uint48();

#endif
