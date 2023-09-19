/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_DUMPMEMORY__
#define __HOTPLACE_SDK_BASE_BASIC_DUMPMEMORY__

#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <string>

namespace hotplace {

/**
 * @brief dump memory
 * @example
 *  const char* data = "hello world\n wide world\n";
 *
 *  buffer_stream bs;
 *  dump_memory ((byte_t*) data, strlen (data), &bs, 16, 0, 0x0, dump_memory_flag_t::header);
 *  std::cout << bs.c_str () << std::endl;
 */

enum dump_memory_flag_t {
    header = (1 << 0),
};

return_t dump_memory (const byte_t* dump_address, size_t dump_size, stream_t* stream_object,
                      unsigned hex_part = 16,
                      unsigned indent = 0,
                      size_t rebase = 0x0,
                      int flags = 0);

}

#endif
