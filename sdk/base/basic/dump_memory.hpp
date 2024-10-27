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

#include <sdk/base/basic/variant.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/stream/printf.hpp>
#include <string>

namespace hotplace {

/**
 * @brief dump memory
 * @example
 *  const char* data = "hello world\n wide world\n";
 *
 *  basic_stream bs;
 *  dump_memory ((byte_t*) data, strlen (data), &bs, 16, 0, 0x0, dump_memory_flag_t::header);
 *  std::cout << bs << std::endl;
 */

enum dump_memory_flag_t {
    dump_header = (1 << 0),
    dump_notrunc = (1 << 1),
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

return_t dump_memory(const char* data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(const std::string& data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(const binary_t& data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(const basic_stream& data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(bufferio_context_t* context, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(variant_t vt, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);

}  // namespace hotplace

#endif
