/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_STREAM_STREAM__
#define __HOTPLACE_SDK_STREAM_STREAM__

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace io {

enum filestream_flag_t {
    flag_normal = 0,
    flag_write = 1 << 0,               /* write                */
    flag_exclusive_flock = 1 << 1,     /* open w/ lock         */
    flag_create_if_not_exist = 1 << 2, /* create if not exists */
    flag_create_always = 1 << 3,       /* always create        */
    flag_share_flock = 1 << 4,         /* open w/ lock         */

    open_existing = flag_normal,
    open_readonly = flag_normal,
    open_create = flag_create_if_not_exist | flag_write,
    open_write = flag_create_if_not_exist | flag_write,
    open_create_always = flag_create_always | flag_write,
    exclusive_read = flag_normal | flag_exclusive_flock,
    exclusive_write = flag_create_if_not_exist | flag_write | flag_exclusive_flock,
    exclusive_create = flag_create_always | flag_write | flag_exclusive_flock,
    share_read = flag_normal | flag_share_flock,
    share_write = flag_create_if_not_exist | flag_write | flag_share_flock,
    share_create = flag_create_always | flag_write | flag_share_flock,
};

#define FILE_BEGIN 0
#define FILE_CURRENT 1
#define FILE_END 2

//
// part - dump
//

return_t dump_memory(const char* data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(const std::string& data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(const binary_t& data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(const basic_stream& data, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(bufferio_context_t* context, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);
return_t dump_memory(variant_t vt, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0, size_t rebase = 0x0, int flags = 0);

}  // namespace io
}  // namespace hotplace

#endif
