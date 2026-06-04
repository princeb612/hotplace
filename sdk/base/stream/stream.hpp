/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   stream.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_STREAM__
#define __HOTPLACE_SDK_BASE_STREAM_STREAM__

#include <hotplace/sdk/base/nostd/traits_encoder.hpp>
#include <hotplace/sdk/base/stream.hpp>

namespace hotplace {

namespace custom {

template <>
struct encoder_stream_traits<stream_t*> {
    typedef char value_type;

    static constexpr bool value = true;
    static void trunc(stream_t* buf) { buf->resize(0); }
    static value_type* reserve(stream_t* buf, size_t size_reserve) {
        size_t pos = buf->size();
        buf->resize(pos + size_reserve);
        return (char*)buf->data() + pos;
    }
    static void commit(stream_t* buf, size_t size_reserve, size_t size_written) {
        if (size_written < size_reserve) {
            buf->resize(buf->size() - (size_reserve - size_written));
        }
    }

    static void preempt(stream_t* buf, size_t size) {}
    static void push(stream_t* buf, value_type c) { buf->write(&c, sizeof(value_type)); }
    static void append(stream_t* buf, const char* msg) {
        if (msg) {
            auto len = strlen(msg);
            buf->write(msg, len);
        }
    }
};

}  // namespace custom

}  // namespace hotplace

#endif
