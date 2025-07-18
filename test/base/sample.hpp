#ifndef __HOTPLACE_TEST_BASE__
#define __HOTPLACE_TEST_BASE__

#include <stdio.h>

#include <functional>
#include <iostream>
#include <sdk/sdk.hpp>
#include <string>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;

void test_sharedinstance1();
void test_sharedinstance2();
void test_convert_endian();
void test_endian();
void test_byte_capacity_unsigned();
void test_byte_capacity_signed();
void test_maphint();
void test_binary();
void test_loglevel();
void test_nostd();
void test_range();
void test_merge();

#endif
