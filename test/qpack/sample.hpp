#ifndef __HOTPLACE_TEST_QPACK__
#define __HOTPLACE_TEST_QPACK__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void dump_qpack_session_routine(const char* stream, size_t size);

void test_expect(binary_t& bin, const char* expect, const char* func, const char* text, ...);
void test_dump(binary_t& bin, const char* text, ...);
void dump(const qpack_decode_t& item);

void test_rfc9204_b();
void test_zero_capacity();
void test_tiny_capacity();
void test_small_capacity();

void test_qpack_stream();

#endif
