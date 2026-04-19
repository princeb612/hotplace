/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_NET_HTTP__
#define __HOTPLACE_TEST_NET_HTTP__

#include <hotplace/testcase/test.hpp>

struct testvector_http_t {
    tls_direction_t dir;
    const char* desc;
    const char* frame;
};

extern const testvector_http_t testvector_h2frame[];
extern const size_t sizeof_testvector_h2;

#endif
