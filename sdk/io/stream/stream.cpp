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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

return_t split(const binary_t& stream, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return split(&stream[0], stream.size(), fragment_size, fn);
}

return_t split(const byte_t* stream, size_t size, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) || (0 == fragment_size) || (nullptr == fn)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined DEBUG
        if (check_trace_level(2) && istraceable()) {
            basic_stream dbs;
            dbs.println("> split [stream = size 0x%zx(%zi)]", size, size);
            dump_memory(stream, size, &dbs, 16, 3, 0, dump_notrunc);
            trace_debug_event(trace_category_internal, trace_event_internal, &dbs);
        }
#endif

        size_t offset = 0;
        for (size_t offset = 0; offset < size; offset += fragment_size) {
            auto remains = size - offset;
            size_t blocksize = 0;
            if (remains >= fragment_size) {
                blocksize = fragment_size;
            } else {
                blocksize = remains;
            }
            fn(stream, size, offset, blocksize);

#if defined DEBUG
            if (check_trace_level(2) && istraceable()) {
                basic_stream dbs;
                dbs.println("> split [fragment = unit 0x%zx(%zi) offset 0x%zx(%zi) size 0x%zx(%zi)]", fragment_size, fragment_size, offset, offset, blocksize,
                            blocksize);
                dump_memory(stream + offset, blocksize, &dbs, 16, 3, 0, dump_notrunc);
                trace_debug_event(trace_category_internal, trace_event_internal, &dbs);
            }
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split(const binary_t& stream, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return split(&stream[0], stream.size(), fragment_size, pre, fn);
}

return_t split(const byte_t* stream, size_t size, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) || (0 == fragment_size) || (nullptr == fn)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t offset = 0;
        size_t blocksize = 0;
        for (size_t offset = 0; offset < size; offset += blocksize) {
            auto remains = size - offset;
            if (0 == offset) {
                blocksize = fragment_size - pre;
            } else {
                blocksize = fragment_size;
            }
            if (remains >= blocksize) {
                fn(stream, size, offset, blocksize);
            } else {
                fn(stream, size, offset, remains);
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
