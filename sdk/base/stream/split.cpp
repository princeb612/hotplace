/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/stream/split.hpp>
#include <sdk/base/unittest/trace.hpp>

namespace hotplace {
namespace io {

return_t split(const binary_t& stream, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return split(&stream[0], stream.size(), fragment_size, 0, fn);
}

return_t split(const byte_t* stream, size_t size, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return split(stream, size, fragment_size, 0, fn);
}

return_t split(const binary_t& stream, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return split(&stream[0], stream.size(), fragment_size, pre, fn);
}

return_t split(const byte_t* stream, size_t size, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((size && (nullptr == stream)) || (0 == fragment_size) || (nullptr == fn)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == size) {
            fn(stream, size, 0, 0);
        } else {
            size_t offset = 0;
            size_t blocksize = 0;
            for (size_t offset = 0; offset < size; offset += blocksize) {
                auto remains = size - offset;
                blocksize = (0 == offset) ? (fragment_size - pre) : fragment_size;
                if (remains < blocksize) {
                    blocksize = remains;
                }
                fn(stream, size, offset, blocksize);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
