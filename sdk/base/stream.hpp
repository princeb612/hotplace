/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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

enum stream_type_t {
    undefined = 0,
    memory = 1,
    file = 2,
};

class stream_t {
   public:
    virtual ~stream_t() {}

    virtual byte_t *data() const = 0;
    virtual uint64 size() const = 0;
    virtual return_t write(const void *data, size_t size) = 0;
    virtual return_t fill(size_t l, char c) = 0;
    virtual return_t clear() = 0;
    virtual bool empty() = 0;
    virtual bool occupied() = 0;

    virtual return_t printf(const char *buf, ...) = 0;
    virtual return_t vprintf(const char *buf, va_list ap) = 0;
    virtual void autoindent(uint8 indent) = 0;
};

}  // namespace hotplace

#endif
