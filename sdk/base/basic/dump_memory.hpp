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

#include <sdk/base/charset.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/types.hpp>
#include <string>

namespace hotplace {

/**
 * @brief dump memory
 * @example
 *  const char* data = "hello world\n wide world\n";
 *
 *  basic_stream bs;
 *  dump_memory ((byte_t*) data, strlen (data), &bs, 16, 0, 0x0, dump_memory_flag_t::header);
 *  std::cout << bs.c_str () << std::endl;
 */

enum dump_memory_flag_t {
    header = (1 << 0),
};

/**
 * @brief   dump memory
 * @param   const byte_t* dump_address [in]
 * @param   size_t dump_size [in]
 * @param   stream_t* stream_object [out]
 * @param   unsigned hex_part [inopt]
 * @param   unsigned indent [inopt]
 * @param   size_t rebase [inopt]
 * @param   int flags [inopt]
 */
return_t dump_memory(const byte_t* dump_address, size_t dump_size, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0,
                     int flags = 0);

}  // namespace hotplace

#endif
