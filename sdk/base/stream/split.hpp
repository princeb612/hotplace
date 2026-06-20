/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   split.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_SPLIT__
#define __HOTPLACE_SDK_BASE_STREAM_SPLIT__

#include <hotplace/sdk/base/stream/types.hpp>

namespace hotplace {
namespace io {

enum splitter_flag_t : uint32 {
    splitter_noalloc = 1 << 0,      // splitter::add
    splitter_new_segment = 1 << 7,  // splitter::run
    splitter_new_group = 1 << 8,    // splitter::run
};

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
