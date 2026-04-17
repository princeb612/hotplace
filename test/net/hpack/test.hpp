/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_NET_HPACK__
#define __HOTPLACE_TEST_NET_HPACK__

#include <hotplace/test/test.hpp>

extern t_shared_instance<hpack_encoder> encoder;

void dump_hpack_session_routine(const char* stream, size_t size);

#endif
