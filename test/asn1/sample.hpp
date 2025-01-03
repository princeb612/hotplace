#ifndef __HOTPLACE_TEST_ASN1__
#define __HOTPLACE_TEST_ASN1__

#include <stdio.h>

#include <algorithm>
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

void test_x690_8_1_3_length_octets();
void test_x690_8_1_5_end_of_contents();
void test_x690_encoding_value();
void test_x690_encoding_typevalue();
void test_x690_constructed();
void test_x690_8_9_sequence();
void test_x690_time();
void test_asn1_object();
void test_x690_annex_a_1();
void test_x690_annex_a_2();

#endif
