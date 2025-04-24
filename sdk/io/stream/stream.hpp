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

#include <sdk/base/stream/types.hpp>

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

/**
 * @brief split
 * @param const byte_t* stream [in]
 * @param size_t size [in]
 * @param size_t fragment_size [in]
 * @param std::function<void(const byte_t*, size_t, size_t, size_t)> fn [in]
 *              const byte_t* stream
 *              size_t size
 *              size_t fragment_offset
 *              size_t fragment_size
 */
return_t split(const binary_t& stream, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);
return_t split(const byte_t* stream, size_t size, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);
/**
 * @brief split
 * @param const byte_t* stream [in]
 * @param size_t size [in]
 * @param size_t fragment_size [in]
 * @param size_t pre [in]
 *                          case fragment_size 50
 *                            if size of last block of previous stream 30
 *                            size of first block of current stream 20 (not 50)
 * @param std::function<void(const byte_t*, size_t, size_t, size_t)> fn [in]
 */
return_t split(const binary_t& stream, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);
return_t split(const byte_t* stream, size_t size, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);

}  // namespace io
}  // namespace hotplace

#endif
