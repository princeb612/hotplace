/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   stream.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM__
#define __HOTPLACE_SDK_BASE_STREAM__

#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <iostream>

namespace hotplace {

enum class stream_type_t {
    undefined = 0,
    memory = 1,
    file = 2,
};

class stream_t {
   public:
    virtual ~stream_t() = default;

    virtual byte_t* data() const = 0;
    virtual uint64 size() const = 0;
    virtual return_t write(const void* data, size_t size) = 0;
    virtual return_t fill(size_t l, char c) = 0;
    virtual return_t clear() = 0;
    virtual bool empty() const = 0;
    virtual bool occupied() const = 0;

    virtual return_t printf(const char* buf, ...) = 0;
    virtual return_t vprintf(const char* buf, va_list ap) = 0;
    virtual void autoindent(uint8 indent) = 0;
    virtual void resize(size_t size) = 0;

    // Reserve writable storage and report failure before callers write through the returned pointer.
    virtual return_t reserve(size_t size_reserve, byte_t** output) {
        if (nullptr == output) {
            return errorcode_t::invalid_parameter;
        }
        *output = nullptr;
        size_t pos = static_cast<size_t>(size());
        if (size_reserve > static_cast<size_t>(-1) - pos) {
            return errorcode_t::overflow;
        }
        size_t required = pos + size_reserve;
        resize(required);
        if (size() < required) {
            return errorcode_t::overflow;
        }
        byte_t* base = data();
        if ((nullptr == base) && (required > 0)) {
            return errorcode_t::internal_error;
        }
        *output = (nullptr == base) ? nullptr : base + pos;
        return errorcode_t::success;
    }
};

}  // namespace hotplace

#endif
